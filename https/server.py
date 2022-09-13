import argparse
from cryptography.hazmat.primitives import hashes
from http.server import SimpleHTTPRequestHandler
from https import HTTPSServer
from https import __version__
import os
import sys


VERBOSE = False
REPO_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_CERT = f"{REPO_DIR}/certs/certfile.crt"
DEFAULT_KEY = f"{REPO_DIR}/certs/keyfile.key"


def verbose_print(msg, suppress=False):
    if VERBOSE:
        if not suppress:
            print(f"[+] {msg}")
        else:
            print(f"    {msg}")


def prompt_yn(msg):
    while "Not a valid answer":
        ans = str(input(f"{msg}(y/n) ")).lower().strip()
        if ans[:1] == "y":
            return True
        elif ans[:1] == "n":
            return False
        print(f"'{ans}' is not a valid response")


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    cert_group = parser.add_argument_group(
        "Certificate Options",
        "Generate a new cert or choose an existing cert to use",
    )
    parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default="0.0.0.0",
        action="store",
        help="Network interface to use",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=8000,
        action="store",
        help="Port to liston on",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print extra info"
    )
    parser.add_argument(
        "--version", action="store_true", help="Print version info"
    )

    cert_group.add_argument(
        "--generate",
        "-g",
        action="store_true",
        help="Generate a new self-signed cert to use",
    )
    cert_group.add_argument(
        "--key",
        "-k",
        action="store",
        help="File that holds key",
    )
    cert_group.add_argument(
        "--cert",
        "-c",
        action="store",
        help="File that holds certificate",
    )

    args = parser.parse_args(argv)

    if args.generate and (args.key or args.cert):
        parser.exit(1, "ERROR: --generate cannot be used with --key/--cert\n")

    if (args.key or args.cert) and not (args.key and args.cert):
        parser.exit(1, "ERROR: --key and --cert must be used together\n")

    if args.key and not os.path.isfile(args.key):
        parser.exit(1, f"ERROR: --key {args.key} does not exist\n")

    if args.cert and not os.path.isfile(args.cert):
        parser.exit(1, f"ERROR: --cert {args.cert} does not exist\n")

    return args


def main():
    args = parse_args(sys.argv[1:])

    if args.version:
        print(f"quick-https v{__version__}")
        return 0

    if args.verbose:
        global VERBOSE
        VERBOSE = True
        verbose_print("-------------------", True)
        verbose_print("Verbose out enabled")
        verbose_print("-------------------", True)

    interface = args.interface
    port = args.port

    key_file = args.key if args.key else DEFAULT_KEY
    cert_file = args.cert if args.key else DEFAULT_CERT

    if args.generate:
        if args.key or args.cert:
            print("[WARN] Not generating new cert because '--key' or ")
            print("       '--cert' option was given")
        else:
            verbose_print("Generating new self signed certificate")
            key, cert = HTTPSServer.generate_self_signed_cert()
            os.makedirs(os.path.dirname(DEFAULT_KEY), exist_ok=True)
            HTTPSServer.write_key_cert(key, DEFAULT_KEY, cert, DEFAULT_CERT)
    else:
        if os.path.isfile(cert_file) and os.path.isfile(key_file):
            key, cert = HTTPSServer.read_key_cert(key_file, cert_file)
        else:
            if prompt_yn(
                "Cert/Key pair does not exist, do you want to generate one?"
            ):
                key, cert = HTTPSServer.generate_self_signed_cert()
                os.makedirs(os.path.dirname(DEFAULT_KEY), exist_ok=True)
                HTTPSServer.write_key_cert(key, key_file, cert, cert_file)
            else:
                print("Certificate/Key pair required to run")
                print("Generate a self-signed cert with '--generate'")
                print("Or specificy cert and key to use")
                quit(1)

    verbose_print("-------------------------------------------------", True)
    verbose_print(f"Interface: {interface}")
    verbose_print(f"Port:      {port}")
    verbose_print(f"Key Size:  {key.public_key().key_size}")
    verbose_print(f"Cert:      {cert.fingerprint(hashes.SHA1()).hex(':',1)}")
    verbose_print("-------------------------------------------------\n", True)

    httpd = HTTPSServer.HTTPSServer(
        (interface, port),
        SimpleHTTPRequestHandler,
        key_file,
        cert_file,
    )

    try:
        print(f"Serving HTTPS on {interface}, port {port}...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nRecieved Keyboard Interupt... Shutting Down")
        httpd.server_close()


if __name__ == "__main__":
    exit(main())
