# Local development authority diagnostics

Explicit local development receivers emit one fixed JSON line after a rejected POST response is complete and its body-admission slot is released. The existing --local-dev-untrusted composition selects this behavior; there is no new flag, logger configuration or framework. Only allow_local_dev is True with the exact builtin LocalDevUntrustedVerifier emits. Other verifier modes remain silent.

Optional internal DomainError diagnostic_reason does not change its code, args, string, explicit cause or retryability. Legacy construction retains its original instance shape. The POST catch retains the error reference without inspecting it for diagnostics, then performs the unchanged generic reply and existing admission release. Only afterward does the emitter accept an exact builtin string code equal to unauthenticated and an exact builtin reason in a closed vocabulary; otherwise it emits no line or a fixed unclassified reason. Legacy generic handling of unknown codes is unchanged.

Metadata is absent from HTTP status/schema/detail/request ID/retryability. The fixed line contains only event, code and a static reason. Error text, traceback, request/body/evidence, identifiers, token/session/nonce, key data and clock values are never emission fields.

The authority acceptance predicate and60second maximum lifetime are unchanged. Only inside its already-denied time branch, the same validated values and supplied clock sample select invalid lifetime first, then future-issued, otherwise expired. This primary-reason priority is not an exhaustive cause report and introduces no tolerance or new authority clock read.

The emitter captures the current stderr stream, writes a prebuilt constant JSON line plus newline and flushes that same stream under ordinary Exception containment. Product code does not use standard logging: StreamHandler.handleError can itself print traceback/error material when a sink fails, outside its caller boundary. There is no logging configuration or global raiseExceptions change. BaseException controls remain effective.

The existing public SOP provider captures stderr in its owned provider.log, already capped at4MiB by its unchanged supervisor. No provider, fixture, guard, timeout or capture budget changes are included. A failing write may leave no or partial diagnostic content; no fallback or recursive error output is attempted. A synchronous sink can still block its handler thread. This adds no global volume/rate limit, queue or unique request correlation. Concurrent static lines carry no request IDs or clock values. A later reason cannot retroactively establish a historical failed attempt cause.

This change supplies diagnostics only. It does not relax authorization, qualify Native authority, fix a proved authentication defect, replay an old SOP or confer Gate credit.
