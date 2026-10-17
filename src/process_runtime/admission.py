"""Receiver-owned new-run admission; composition flags never confer authority."""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

SCHEMA = 'runtime.new-run-admission.v1'
MAX_BYTES = 4096


class AdmissionPolicyError(ValueError):
    pass


def canonical_policy(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate_policy(value):
    if (type(value) is not dict or set(value) != {'schema', 'enabled', 'composition_digest'}
            or value['schema'] != SCHEMA or type(value['enabled']) is not bool
            or type(value['composition_digest']) is not str or len(value['composition_digest']) != 64
            or any(c not in '0123456789abcdef' for c in value['composition_digest'])):
        raise AdmissionPolicyError('Unsupported new-run admission policy')
    return value


def private_stat(info, *, directory=False):
    if (info.st_uid != os.getuid() or info.st_mode & 0o077
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise AdmissionPolicyError('Admission policy requires owner-private files and directory')


def policy_path(path):
    path = Path(path)
    if not path.is_absolute():
        raise AdmissionPolicyError('Admission policy path must be absolute')
    private_stat(path.parent.lstat(), directory=True)
    return path


@contextmanager
def policy_lock(path, *, exclusive=False):
    path = policy_path(path)
    fd = os.open(str(path) + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        private_stat(os.fstat(fd))
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield path
    finally:
        os.close(fd)


def read_policy(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        private_stat(os.fstat(fd))
        with os.fdopen(fd, 'rb', closefd=False) as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise AdmissionPolicyError('Admission policy is oversized')
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise AdmissionPolicyError('Duplicate admission policy field')
                value[key] = item
            return value
        value = json.loads(raw, object_pairs_hook=pairs)
        validate_policy(value)
        return value, hashlib.sha256(canonical_policy(value)).hexdigest()
    finally:
        os.close(fd)


@dataclass(frozen=True)
class StaticAdmissionGate:
    enabled: bool

    def __post_init__(self):
        if type(self.enabled) is not bool:
            raise AdmissionPolicyError('Admission must be an explicit boolean')

    @contextmanager
    def hold(self):
        yield self.enabled

    def status(self):
        return {'new_runs': 'open' if self.enabled else 'closed', 'source': 'static'}


class FileAdmissionGate:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_absolute():
            raise AdmissionPolicyError('Admission policy path must be absolute')

    @contextmanager
    def hold(self):
        # The shared lock remains held through runtime transaction commit. The
        # operator's exclusive update waits for already admitted transactions.
        with ExitStack() as scope:
            try:
                path = scope.enter_context(policy_lock(self.path))
                value, _ = read_policy(path)
                allowed = value['enabled']
            except (OSError, ValueError, UnicodeError, RecursionError):
                allowed = False
            yield allowed

    def status(self):
        try:
            with policy_lock(self.path) as path:
                value, digest = read_policy(path)
                return {'new_runs': 'open' if value['enabled'] else 'closed', 'source': 'file', 'policy_digest': digest,
                        'composition_digest': value['composition_digest']}
        except (OSError, ValueError, UnicodeError, RecursionError):
            return {'new_runs': 'closed', 'source': 'file', 'reason': 'policy_unavailable'}


def apply_policy(path, value, *, expected_digest):
    """CAS policy replacement; never reads or changes runtime business stores."""
    value = validate_policy(value)
    with policy_lock(path, exclusive=True) as path:
        try:
            _, current = read_policy(path)
        except FileNotFoundError:
            current = None
        if current != expected_digest:
            raise AdmissionPolicyError('Admission policy changed during review')
        raw = canonical_policy(value)
        fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as target:
                target.write(raw); target.flush(); os.fsync(target.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return {'policy_digest': hashlib.sha256(raw).hexdigest(), 'enabled': value['enabled'],
                'composition_digest': value['composition_digest']}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Receiver-owned new-run admission policy operator')
    parser.add_argument('action', choices=('check', 'apply'))
    parser.add_argument('--policy', required=True)
    parser.add_argument('--request-file')
    args = parser.parse_args(argv)
    try:
        if args.action == 'check':
            result = {'schema': 'runtime.new-run-admission-result.v1', 'status': FileAdmissionGate(args.policy).status()}
        else:
            if not args.request_file:
                raise AdmissionPolicyError('Apply requires an exact private request file')
            file = Path(args.request_file)
            fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                private_stat(os.fstat(fd))
                with os.fdopen(fd, 'rb', closefd=False) as source:
                    raw = source.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise AdmissionPolicyError('Operator request is oversized')
                def pairs(items):
                    value = {}
                    for key, item in items:
                        if key in value:
                            raise AdmissionPolicyError('Duplicate operator request field')
                        value[key] = item
                    return value
                value = json.loads(raw, object_pairs_hook=pairs)
            finally:
                os.close(fd)
            if (type(value) is not dict or set(value) != {'schema', 'policy', 'expected_digest'}
                    or value['schema'] != 'runtime.new-run-admission-apply.v1'):
                raise AdmissionPolicyError('Unsupported admission operator request')
            expected = value['expected_digest']
            if expected is not None and (type(expected) is not str or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected)):
                raise AdmissionPolicyError('Expected policy digest is invalid')
            result = {'schema': 'runtime.new-run-admission-result.v1',
                      'data': apply_policy(args.policy, value['policy'], expected_digest=expected)}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError, RecursionError):
        parser.exit(2, 'Admission policy operation rejected\n')


if __name__ == '__main__':
    raise SystemExit(main())
