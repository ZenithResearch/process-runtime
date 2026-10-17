"""Local composition entry point. Production defaults to deny-all authority."""
import argparse
import threading
from .admission import FileAdmissionGate
from .application import Runtime
from .authority import DEFAULT_AUDIENCE, LocalDevUntrustedVerifier
from .receiver_config import load_receiver_configuration
from .http_api import make_server
from .sqlite_store import SQLiteStore


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--port", type=int, default=8092)
    parser.add_argument("--environment", choices=("production", "development", "test"), default="production")
    parser.add_argument("--local-dev-untrusted", action="store_true")
    parser.add_argument("--local-dev-subject", default="local-runtime-developer")
    parser.add_argument("--admission-policy", help="Absolute owner-private new-run admission policy")
    parser.add_argument("--receiver-config", help="Absolute owner-private native receiver configuration")
    args = parser.parse_args(argv)
    if args.environment == "production" and args.local_dev_untrusted:
        parser.error("local_dev_untrusted is prohibited in production")
    if args.receiver_config is not None and args.local_dev_untrusted:
        parser.error("Receiver configuration cannot be combined with local development authority")
    store = None
    try:
        verifier = (load_receiver_configuration(args.receiver_config) if args.receiver_config is not None else
                    LocalDevUntrustedVerifier(args.local_dev_subject) if args.local_dev_untrusted else None)
        admission = FileAdmissionGate(args.admission_policy) if args.admission_policy is not None else None
        # Invalid receiver configuration rejects before creating/opening storage.
        store = SQLiteStore(args.database)
        runtime = Runtime(store, verifier=verifier, environment=args.environment,
                          allow_local_dev_untrusted=args.local_dev_untrusted,
                          audience=getattr(verifier, "audience", DEFAULT_AUDIENCE),
                          new_run_admission=admission)
        server = make_server(runtime, port=args.port)
    except (OSError, ValueError):
        if store is not None:
            store.close()
        parser.error("Runtime receiver initialization rejected")
    stopped = threading.Event()
    def recovery():
        while not stopped.wait(1):
            try:
                runtime.recover()
            except Exception:
                # Readiness detects storage failure; no exception payload/key is logged.
                pass
    worker = threading.Thread(target=recovery, daemon=True)
    worker.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stopped.set(); worker.join(timeout=5); server.server_close(); store.close()

if __name__ == "__main__":
    main()
