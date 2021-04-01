import argparse
import random
import ssl
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

VERBOSE = False
CIPHERS = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:\
           ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:\
           DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:\
           ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:\
           ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:\
           ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:\
           ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:\
           DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:\
           DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"


def verbose_print(msg, suppress=False):
    if VERBOSE:
        if suppress:
            print(f"    {msg}")
        else:
            print(f"[+] {msg}")


def generate_self_signed_cert():
    server_ip = "127.0.0.1"
    host_name = "ca_server"

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host_name)])

    alt_names = [x509.DNSName(host_name)]
    alt_names.append(x509.DNSName(server_ip))

    basic_constraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(random.getrandbits(159))
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=7))
        .add_extension(basic_constraints, True)
        .add_extension(x509.SubjectAlternativeName(alt_names), False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    return key, cert


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
    """
    Removing key file arguments to generate a new key every time.
    These can be added back in the future

    parser.add_argument(
        "--generate",
        "-g",
        action="store_true",
        help="Generate a new self-signed cert to use",
    )
    parser.add_argument(
        "--key-file",
        "-k",
        type=str,
        default="example_cert/keyfile.key",
        action="store",
        help="Keyfile",
    )
    parser.add_argument(
        "--cert-file",
        "-c",
        type=str,
        default="example_cert/certfile.crt",
        action="store",
        help="Certfile",
    )
    """
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Print extra info"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        global VERBOSE
        VERBOSE = True
        verbose_print("Verbose out enabled")
        verbose_print("-------------------", True)

    interface = args.interface
    port = args.port

    key, cert = generate_self_signed_cert()
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open("certs/certfile.crt", "wb") as f:
        f.write(cert_pem)
    with open("certs/keyfile.key", "wb") as f:
        f.write(key_pem)

    verbose_print(f"Interface: {interface}")
    verbose_print(f"Port:      {port}")
    verbose_print(f"Key Size:  {key.public_key().key_size}")
    verbose_print(f"Cert:      {cert.fingerprint(hashes.SHA1()).hex(':',1)}")
    verbose_print("\n", True)

    httpd = TCPServer((interface, port), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile="certs/keyfile.key",
        certfile="certs/certfile.crt",
        server_side=True,
        ssl_version=ssl.PROTOCOL_TLSv1_2,
        ca_certs=None,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
    )
    try:
        print(f"Serving HTTPS on {interface}, port {port}...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nRecieved Keyboard Interupt... Shutting Down")
        httpd.server_close()


if __name__ == "__main__":
    main()
