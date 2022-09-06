import argparse
from cryptography.hazmat.primitives import hashes
from http.server import SimpleHTTPRequestHandler
from https import HTTPSServer
import os


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


def parse_args():
    parser = argparse.ArgumentParser()
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
        "--generate",
        "-g",
        action="store_true",
        help="Generate a new self-signed cert to use",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Print extra info"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        global VERBOSE
        VERBOSE = True
        verbose_print("-------------------", True)
        verbose_print("Verbose out enabled")
        verbose_print("-------------------", True)

    interface = args.interface
    port = args.port

    if args.generate:
        verbose_print("Generating new self signed certificate")
        key, cert = HTTPSServer.generate_self_signed_cert()
        HTTPSServer.write_key_cert(key, DEFAULT_KEY, cert, DEFAULT_CERT)
    else:
        if os.path.isfile(DEFAULT_CERT) and os.path.isfile(DEFAULT_KEY):
            key, cert = HTTPSServer.read_key_cert(DEFAULT_KEY, DEFAULT_CERT)
        else:
            if prompt_yn(
                "Cert/Key pair does not exist, do you want to generate one?"
            ):
                key, cert = HTTPSServer.generate_self_signed_cert()
                HTTPSServer.write_key_cert(
                    key, DEFAULT_KEY, cert, DEFAULT_CERT
                )
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
        DEFAULT_KEY,
        DEFAULT_CERT,
    )

    try:
        print(f"Serving HTTPS on {interface}, port {port}...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nRecieved Keyboard Interupt... Shutting Down")
        httpd.server_close()


if __name__ == "__main__":
    exit(main())
