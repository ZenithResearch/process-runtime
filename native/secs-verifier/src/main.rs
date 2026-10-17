//! Verification-only stdin/stdout adapter. No key custody, issuing, networking,
//! configuration discovery, clock reads, filesystem state or replay admission.
use bincode::Options;
use ed25519_dalek::VerifyingKey;
use libsec_core::ZenithPacket;
use secs_server::identity::{PublicVerifierKey, PublicVerifierKeyRegistry, VerificationKeyStatus};
use secs_server::verifier::{SignedVerifiedCallContext, VERIFIED_CALL_CONTEXT_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 16_384;
const PACKET_FIXED_BYTES: usize = 69;
const MAX_PACKET_BYTES: usize = MAX_REQUEST_BYTES + MAX_PROOF_BYTES + PACKET_FIXED_BYTES;
const MAX_CONTEXT_BYTES: usize = 65_536;
const MAX_METADATA_BYTES: usize = 65_536;
const MAX_OUTPUT_BYTES: usize = 131_072;
const MAX_INPUT: u64 = 9 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Key {
    key_id: String,
    public_key_hex: String,
    status: String,
    production_authority: bool,
    not_before: Option<u64>,
    not_after: Option<u64>,
    revoked_at: Option<u64>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema: String,
    packet_hex: String,
    signed_context_hex: String,
    request_hex: String,
    audience: String,
    now_seconds: u64,
    keys: Vec<Key>,
}

#[derive(Serialize)]
struct Output {
    schema: &'static str,
    context: secs_server::verifier::VerifiedCallContext,
    signer_key_id: String,
    authenticator_kind: &'static str,
}

fn decode(text: &str, max: usize) -> Result<Vec<u8>, &'static str> {
    if text.len() > max * 2
        || text.len() % 2 != 0
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid_envelope");
    }
    hex::decode(text).map_err(|_| "invalid_envelope")
}

fn check(input: Input) -> Result<Output, &'static str> {
    if input.schema != "process-runtime.secs-check-input.v1"
        || input.now_seconds == 0
        || input.keys.is_empty()
        || input.keys.len() > 32
    {
        return Err("invalid_configuration");
    }
    // Count the complete closed JSON framing and typed metadata independently
    // of the three bounded hex bodies, including any JSON escaping in labels.
    let metadata = serde_json::json!({"schema": &input.schema, "packet_hex": "",
        "signed_context_hex": "", "request_hex": "", "audience": &input.audience,
        "now_seconds": input.now_seconds, "keys": &input.keys});
    if serde_json::to_vec(&metadata)
        .map_err(|_| "invalid_configuration")?
        .len()
        > MAX_METADATA_BYTES
    {
        return Err("metadata_too_large");
    }
    let packet_bytes = decode(&input.packet_hex, MAX_PACKET_BYTES)?;
    let context_bytes = decode(&input.signed_context_hex, MAX_CONTEXT_BYTES)?;
    let request = decode(&input.request_hex, MAX_REQUEST_BYTES)?;
    let packet: ZenithPacket = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_PACKET_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&packet_bytes)
        .map_err(|_| "invalid_packet")?;
    let signed: SignedVerifiedCallContext = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_CONTEXT_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&context_bytes)
        .map_err(|_| "invalid_context")?;
    if packet.proof.len() > MAX_PROOF_BYTES {
        return Err("proof_too_large");
    }
    if bincode::serialize(&packet).map_err(|_| "invalid_packet")? != packet_bytes
        || bincode::serialize(&signed).map_err(|_| "invalid_context")? != context_bytes
    {
        return Err("noncanonical_native_bytes");
    }
    let mut keys = Vec::new();
    for configured in input.keys {
        let bytes: [u8; 32] = decode(&configured.public_key_hex, 32)?
            .try_into()
            .map_err(|_| "invalid_configuration")?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid_configuration")?;
        let status = match configured.status.as_str() {
            "active" => VerificationKeyStatus::Active,
            "revoked" => VerificationKeyStatus::Revoked,
            "expired" => VerificationKeyStatus::Expired,
            _ => return Err("invalid_configuration"),
        };
        // Native registry's historical not_after check is inclusive. This
        // receiver uses an exclusive expiry boundary, consistent with leases.
        if configured.key_id == signed.signer_key_id
            && configured
                .not_after
                .is_some_and(|end| input.now_seconds >= end)
        {
            return Err("expired_verifier_key");
        }
        keys.push(
            PublicVerifierKey::active(configured.key_id, "ed25519", key)
                .with_status(status)
                .with_production_authority(configured.production_authority)
                .with_validity_window(configured.not_before, configured.not_after)
                .with_revoked_at(configured.revoked_at),
        );
    }
    PublicVerifierKeyRegistry::from_keys(keys)
        .verify_production_signed_context(&signed, &input.audience, input.now_seconds)
        .map_err(|_| "untrusted_context")?;
    let context = &signed.context;
    let packet_hash: [u8; 32] = Sha256::digest(&packet_bytes).into();
    if context.schema_version != VERIFIED_CALL_CONTEXT_SCHEMA_VERSION
        || context.schema_version != 4
        || context.packet_hash != packet_hash
        || context.session_id != packet.session_id
        || context.nonce != packet.nonce
        || context.opcode != packet.opcode
        || packet.encrypted_payload != request
        || context.replay_scope != "session:opcode:nonce"
        || context.issued_at > input.now_seconds
        || input.now_seconds >= context.expires_at
        || context.expires_at <= context.issued_at
        || context.expires_at - context.issued_at > 60
        || packet.claim_ttl != context.expires_at - context.issued_at
    {
        return Err("context_packet_binding_mismatch");
    }
    Ok(Output {
        schema: "process-runtime.secs-check-output.v1",
        context: signed.context,
        signer_key_id: signed.signer_key_id,
        authenticator_kind: signed.authenticator_kind.as_str(),
    })
}

fn run() -> Result<(), &'static str> {
    if std::env::args_os().len() != 1 {
        return Err("invalid_arguments");
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input_failed")?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err("input_too_large");
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|_| "invalid_input")?;
    let result = check(input)?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "output_failed")?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err("output_too_large");
    }
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|_| "output_failed")
}

fn main() {
    if run().is_err() {
        // Fixed diagnostic: never print caller payloads, proofs or configuration.
        eprintln!("{{\"error\":\"native_authority_rejected\"}}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use secs_server::receipt::AuthenticatorKind;
    use secs_server::verifier::{VerifiedCallContext, VerifiedSubject};
    use serde_json::json;

    fn fixture(request: &str, operation: &str, resource: &str, opcode: u8) -> Input {
        let packet = ZenithPacket {
            session_id: [1; 16],
            nonce: [2; 12],
            opcode,
            proof: vec![3, 4],
            claim_ttl: 60,
            encrypted_payload: request.as_bytes().to_vec(),
            mac: [0; 16],
        };
        let packet_bytes = bincode::serialize(&packet).unwrap();
        let context = VerifiedCallContext {
            schema_version: 4,
            context_id: "synthetic-context".into(),
            packet_hash: Sha256::digest(&packet_bytes).into(),
            session_id: packet.session_id,
            nonce: packet.nonce,
            opcode,
            operation: operation.into(),
            resource: Some(resource.into()),
            subject: VerifiedSubject {
                subject_id: "synthetic-subject".into(),
                key_id: "synthetic-holder".into(),
            },
            audience: "runtime://receiver-local".into(),
            evidence_summary: vec![],
            proof_metadata: None,
            capability_result: "runtime.execute".into(),
            credential_result: "runtime.executor".into(),
            issued_at: 1000,
            expires_at: 1060,
            descriptor_fingerprint: "a".repeat(64),
            replay_scope: "session:opcode:nonce".into(),
            handler_id: Some("runtime-v1".into()),
        };
        // Synthetic fixture seed only; this code is excluded from shipped binary.
        let signed = context
            .sign_ed25519(
                "synthetic-verifier",
                &[17; 32],
                AuthenticatorKind::Ed25519NodeAndVerifier,
            )
            .unwrap();
        Input {
            schema: "process-runtime.secs-check-input.v1".into(),
            packet_hex: hex::encode(packet_bytes),
            signed_context_hex: hex::encode(bincode::serialize(&signed).unwrap()),
            request_hex: hex::encode(request),
            audience: "runtime://receiver-local".into(),
            now_seconds: 1001,
            keys: vec![Key {
                key_id: "synthetic-verifier".into(),
                public_key_hex: hex::encode(
                    SigningKey::from_bytes(&[17; 32]).verifying_key().as_bytes(),
                ),
                status: "active".into(),
                production_authority: true,
                not_before: Some(999),
                not_after: Some(1200),
                revoked_at: None,
            }],
        }
    }

    fn bounded_fixture(request: &str, proof_size: usize, context_size: usize) -> Input {
        bounded_fixture_for(
            request,
            "runtime.run.create.v1",
            "runs/run-1",
            66,
            proof_size,
            context_size,
        )
    }

    fn bounded_fixture_for(
        request: &str,
        operation: &str,
        resource: &str,
        opcode: u8,
        proof_size: usize,
        context_size: usize,
    ) -> Input {
        let mut input = fixture(request, operation, resource, opcode);
        let mut packet: ZenithPacket =
            bincode::deserialize(&hex::decode(&input.packet_hex).unwrap()).unwrap();
        packet.proof = vec![3; proof_size];
        let packet_bytes = bincode::serialize(&packet).unwrap();
        let mut signed: SignedVerifiedCallContext =
            bincode::deserialize(&hex::decode(&input.signed_context_hex).unwrap()).unwrap();
        signed.context.packet_hash = Sha256::digest(&packet_bytes).into();
        signed.context.evidence_summary = vec![String::new()];
        let sign = |context: &VerifiedCallContext| {
            context
                .clone()
                .sign_ed25519(
                    "synthetic-verifier",
                    &[17; 32],
                    AuthenticatorKind::Ed25519NodeAndVerifier,
                )
                .unwrap()
        };
        let baseline = bincode::serialize(&sign(&signed.context)).unwrap().len();
        assert!(context_size >= baseline);
        signed.context.evidence_summary[0] = "x".repeat(context_size - baseline);
        input.packet_hex = hex::encode(packet_bytes);
        input.signed_context_hex = hex::encode(bincode::serialize(&sign(&signed.context)).unwrap());
        input
    }

    #[test]
    fn maximum_public_request_proof_context_and_adjacent_bounds() {
        let request = "x".repeat(2_097_152);
        let input = bounded_fixture(&request, 16_384, 65_536);
        assert_eq!(input.packet_hex.len() / 2, 2_113_605);
        assert_eq!(input.signed_context_hex.len() / 2, 65_536);
        assert!(check(input.clone()).is_ok());
        let mut over_packet = input.clone();
        over_packet.packet_hex.push_str("00");
        assert!(check(over_packet).is_err());
        let mut over_context = input;
        over_context.signed_context_hex.push_str("00");
        assert!(check(over_context).is_err());
        assert!(check(bounded_fixture(&(request + "x"), 16_384, 65_536)).is_err());
    }

    #[test]
    fn proof_limit_is_independent_of_available_packet_space() {
        assert!(check(bounded_fixture("{}", 16_384, 65_536)).is_ok());
        assert!(check(bounded_fixture("{}", 16_385, 65_536)).is_err());
    }

    #[test]
    fn actual_native_signature_and_exact_packet_binding() {
        let original = fixture("{}", "runtime.run.get.v1", "runs/run-1", 98);
        assert!(check(original.clone()).is_ok());
        for mutate in [0, 1, 2, 3, 4, 5, 6, 7] {
            let mut value = original.clone();
            match mutate {
                0 => value.request_hex = hex::encode("{\"substituted\":true}"),
                1 => value.packet_hex.push_str("00"),
                2 => value.signed_context_hex.push_str("00"),
                3 => value.audience = "other".into(),
                4 => value.now_seconds = 1060,
                5 => value.keys[0].status = "revoked".into(),
                6 => value.keys[0].production_authority = false,
                _ => value.keys.push(value.keys[0].clone()),
            }
            assert!(check(value).is_err(), "variant {mutate}");
        }
        let mut tampered = original;
        let len = tampered.signed_context_hex.len();
        tampered.signed_context_hex.replace_range(len - 2.., "00");
        assert!(check(tampered).is_err());
    }

    #[test]
    fn signed_schema_time_replay_and_local_development_variants_fail_closed() {
        let original = fixture("{}", "runtime.run.get.v1", "runs/run-1", 98);
        for variant in 0..6 {
            let mut input = original.clone();
            let mut signed: SignedVerifiedCallContext =
                bincode::deserialize(&hex::decode(&input.signed_context_hex).unwrap()).unwrap();
            let mut kind = AuthenticatorKind::Ed25519NodeAndVerifier;
            match variant {
                0 => signed.context.schema_version = 3,
                1 => {
                    signed.context.issued_at = 1002;
                    signed.context.expires_at = 1062;
                }
                2 => signed.context.nonce = [9; 12],
                3 => signed.context.opcode = 99,
                4 => signed.context.replay_scope.clear(),
                _ => kind = AuthenticatorKind::LocalDevUntrusted,
            }
            let resigned = signed
                .context
                .sign_ed25519("synthetic-verifier", &[17; 32], kind)
                .unwrap();
            input.signed_context_hex = hex::encode(bincode::serialize(&resigned).unwrap());
            assert!(check(input).is_err(), "signed variant {variant}");
        }
    }

    #[test]
    fn maximum_artifact_request_fits_bounded_native_transport() {
        let input = fixture(
            &"x".repeat(1_400_000),
            "runtime.artifact.put.v1",
            "artifacts/example",
            69,
        );
        assert!(check(input).is_ok());
    }

    #[test]
    fn retained_synthetic_fixtures() {
        let Some(source) = std::env::var_os("RUNTIME_SECS_FIXTURE_INPUT") else {
            return;
        };
        let output = std::env::var_os("RUNTIME_SECS_FIXTURE_OUTPUT").expect("explicit output");
        let cases: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(source).unwrap()).unwrap();
        let mut fixtures = Vec::new();
        for case in cases {
            let input = if case["max_transport"].as_bool() == Some(true) {
                bounded_fixture_for(
                    case["request"].as_str().unwrap(),
                    case["operation"].as_str().unwrap(),
                    case["resource"].as_str().unwrap(),
                    case["opcode"].as_u64().unwrap() as u8,
                    16_384,
                    65_536,
                )
            } else {
                fixture(
                    case["request"].as_str().unwrap(),
                    case["operation"].as_str().unwrap(),
                    case["resource"].as_str().unwrap(),
                    case["opcode"].as_u64().unwrap() as u8,
                )
            };
            assert!(check(input.clone()).is_ok());
            fixtures.push(json!({"name":case["name"], "request":case["request"], "operation":case["operation"], "resource":case["resource"], "opcode":case["opcode"],
                "envelope":{"schema":"runtime.secs-envelope.v1","packet_hex":input.packet_hex,"signed_context_hex":input.signed_context_hex},
                "public_key_hex":input.keys[0].public_key_hex,"now_ms":1001000}));
        }
        std::fs::write(output, serde_json::to_vec_pretty(&json!({"schema":"runtime.synthetic-native-fixtures.v1", "secs_revision":"11e7128e49c6df57f53e4c8b05e72d4bc78d798c", "fixtures":fixtures})).unwrap()).unwrap();
    }
}
