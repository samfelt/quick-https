from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta
from http.server import HTTPServer
import random
import ssl


class HTTPSServer(HTTPServer):
    """Extend HTTPServer to include HTTPS."""

    def __init__(self, address, handler, key_file, cert_file):
        """Intialize the HTTPS server.
        Add a fields for key and cert files to generate ssl context.
        """

        HTTPServer.__init__(self, address, handler)
        ssl_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(
            certfile=cert_file,
            keyfile=key_file,
        )
        self.socket = ssl_ctx.wrap_socket(
            sock=self.socket,
            server_side=True,
            do_handshake_on_connect=True,
            suppress_ragged_eofs=True,
        )


def generate_self_signed_cert(server_ip="127.0.0.1", host_name="ca_server"):
    """Generate a self signed certificate and corresponding private key."""

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


def write_key_cert(key, key_file, cert, cert_file):
    """Write key and certificate files."""

    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(cert_file, "wb") as f:
        f.write(cert_pem)
    with open(key_file, "wb") as f:
        f.write(key_pem)


def read_key_cert(key_file, cert_file):
    """Read key and certificate files."""

    with open(cert_file, "rb") as f:
        cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

    with open(key_file, "rb") as f:
        key_pem = f.read()
        key = serialization.load_pem_private_key(
            key_pem, None, default_backend()
        )

    return key, cert
