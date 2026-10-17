"""Operator-selected public receiver policy; no custody, issuing or trust discovery."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat

from .authority import (NativeSecSHelper, OPCODES, PermissionRule, ReceiverPolicy,
                        SecSExecutionAuthorityVerifier, VerifierKey, _object, operation_name)
from .domain import DomainError, digest

CONFIG_SCHEMA = "runtime.receiver-configuration.v1"
POLICY_SCHEMA = "runtime.receiver-policy.v1"
MAX_CONFIG_BYTES = 65536
MAX_POLICY_BYTES = 262144


class ReceiverConfigurationError(ValueError):
    pass


def _path(value) -> Path:
    if not isinstance(value, (str, Path)):
        raise ReceiverConfigurationError("Receiver paths must be explicit absolute paths")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ReceiverConfigurationError("Receiver paths must be explicit absolute paths")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ReceiverConfigurationError("Receiver paths cannot traverse symlinks")
    return path


def _private_json(path, maximum: int) -> dict:
    path = _path(path)
    for parent in path.parents:
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                or (info.st_mode & 0o022 and not sticky_root)):
            raise ReceiverConfigurationError("Receiver configuration directory is not operator-controlled")
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ReceiverConfigurationError("Receiver configuration requires a private operator directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ReceiverConfigurationError("Receiver configuration requires a private regular file")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(maximum + 1)
        if len(raw) > maximum:
            raise ReceiverConfigurationError("Receiver configuration exceeds its byte bound")
        return _object(raw)
    finally:
        os.close(fd)


def _closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ReceiverConfigurationError("Receiver configuration is closed and explicit")
    return value


def _array(value, maximum):
    if type(value) is not list or len(value) > maximum:
        raise ReceiverConfigurationError("Receiver configuration collection exceeds its bound")
    return value


def _audience(value):
    if (type(value) is not str or not 1 <= len(value) <= 4096
            or any(ord(c) < 32 for c in value) or "*" in value):
        raise ReceiverConfigurationError("Receiver audience must be explicit and bounded")
    return value


class PinnedReceiverHelper(NativeSecSHelper):
    def check_available(self):
        path = _path(self.executable)
        # A root-owned sticky temporary root is permitted for isolated fixtures;
        # other ancestors must be owned by root/operator and non-writable to peers.
        for parent in path.parents:
            info = parent.lstat()
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or (info.st_mode & 0o022 and not sticky_root)):
                raise ReceiverConfigurationError("Native verifier directory is not operator-controlled")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or info.st_mode & 0o022 or not info.st_mode & 0o111
                    or info.st_nlink != 1 or not 0 < info.st_size <= 67108864):
                raise ReceiverConfigurationError("Native verifier must be an operator-controlled executable")
            with os.fdopen(fd, "rb", closefd=False) as source:
                actual = hashlib.file_digest(source, "sha256").hexdigest()
            if actual != self.sha256:
                raise ReceiverConfigurationError("Native verifier bytes differ from the operator pin")
        finally:
            os.close(fd)

    def verify(self, value):
        try:
            self.check_available()
        except (OSError, ValueError, DomainError) as exc:
            raise DomainError("unauthenticated", "Native receiver verification is unavailable") from exc
        return super().verify(value)


class FileReceiverPolicy:
    """Reload public keys, descriptors, grants and revocations for every call."""
    def __init__(self, path, audience):
        self.path, self.audience = _path(path), _audience(audience)

    def __call__(self):
        try:
            value = _closed(_private_json(self.path, MAX_POLICY_BYTES),
                            ("schema", "audience", "keys", "descriptors", "permissions", "revoked_subject_keys"))
            if value["schema"] != POLICY_SCHEMA or _audience(value["audience"]) != self.audience:
                raise ReceiverConfigurationError("Receiver policy audience or version differs")
            keys = []
            for item in _array(value["keys"], 32):
                _closed(item, ("key_id", "public_key_hex", "status", "production_authority", "not_before", "not_after", "revoked_at"))
                key = VerifierKey(**item)
                if key.not_before is not None and key.not_after is not None and key.not_before >= key.not_after:
                    raise ReceiverConfigurationError("Verifier key validity window is invalid")
                keys.append(key)
            if len({key.key_id for key in keys}) != len(keys):
                raise ReceiverConfigurationError("Verifier key identities must be unique")
            descriptors = []
            for item in _array(value["descriptors"], len(OPCODES)):
                _closed(item, ("operation", "fingerprint", "handler_id"))
                descriptors.append((item["operation"], item["fingerprint"], item["handler_id"]))
            rules = []
            for item in _array(value["permissions"], 1024):
                _closed(item, ("subject_id", "operation", "resource", "effect", "not_before_ms", "not_after_ms", "resource_match", "key_id", "active"))
                rules.append(PermissionRule(**item))
            revocations = []
            for item in _array(value["revoked_subject_keys"], 1024):
                _closed(item, ("subject_id", "key_id"))
                revocations.append((item["subject_id"], item["key_id"]))
            if len(set(revocations)) != len(revocations):
                raise ReceiverConfigurationError("Subject key revocations must be unique")
            return ReceiverPolicy(self.audience, tuple(keys), tuple(descriptors), tuple(rules), frozenset(revocations))
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            raise ReceiverConfigurationError("Receiver public policy is unavailable or invalid") from exc


class ConfiguredReceiverVerifier(SecSExecutionAuthorityVerifier):
    def verify(self, *, envelope, command, now_ms):
        try:
            policy = self.load_policy()
            captured = {}
            actual_helper = self.native_helper
            class CaptureSigner:
                def verify(self, value):
                    output = actual_helper.verify(value)
                    captured["signer_key_id"] = output["signer_key_id"]
                    return output
            verified = SecSExecutionAuthorityVerifier(CaptureSigner(), lambda: policy).verify(
                envelope=envelope, command=command, now_ms=now_ms)
            if self.load_policy() != policy:
                raise DomainError("forbidden", "Receiver policy changed during native verification")
            # The kernel rechecks time after helper latency. Its effective deadline
            # must also cover local grant/key windows and impending matching denies.
            matching = [rule for rule in policy.rules if rule.active
                        and rule.subject_id == verified.subject_id
                        and (rule.key_id is None or rule.key_id == verified.key_id)
                        and rule.operation == operation_name(command)
                        and (rule.resource == verified.resource if rule.resource_match == "exact"
                             else verified.resource.startswith(rule.resource))]
            deadlines = [verified.expires_at_ms,
                         max(rule.not_after_ms for rule in matching if rule.effect == "allow"
                             and rule.not_before_ms <= now_ms < rule.not_after_ms)]
            deadlines.extend(rule.not_before_ms for rule in matching
                             if rule.effect == "deny" and rule.not_before_ms > now_ms)
            signer = next(key for key in policy.keys if key.key_id == captured["signer_key_id"])
            deadlines.extend(value * 1000 for value in (signer.not_after, signer.revoked_at)
                             if value is not None)
            return replace(verified, expires_at_ms=min(deadlines))
        except ReceiverConfigurationError as exc:
            raise DomainError("unauthenticated", "Receiver public policy is unavailable") from exc

    def verification_status(self):
        # Syntax and pinned executable availability are not native chain/release qualification.
        try:
            self.native_helper.check_available()
            self.load_policy()
            available = "available"
        except (OSError, ValueError, DomainError):
            available = "unavailable"
        return {"authority": "configured_native_unqualified", "verification": available,
                "qualification": "unqualified"}


def load_receiver_configuration(path) -> ConfiguredReceiverVerifier:
    try:
        value = _closed(_private_json(path, MAX_CONFIG_BYTES),
                        ("schema", "audience", "native_verifier", "policy_file"))
        if value["schema"] != CONFIG_SCHEMA:
            raise ReceiverConfigurationError("Unsupported receiver configuration")
        audience = _audience(value["audience"])
        native = _closed(value["native_verifier"], ("executable", "sha256"))
        helper = PinnedReceiverHelper(_path(native["executable"]), digest(native["sha256"]))
        policy = FileReceiverPolicy(value["policy_file"], audience)
        helper.check_available()
        policy()
        result = ConfiguredReceiverVerifier(helper, policy)
        result.audience = audience
        return result
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        raise ReceiverConfigurationError("Receiver configuration is unavailable or invalid") from exc
