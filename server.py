import argparse
import ssl
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

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
    verbose_print(f"Interface: {interface}")
    verbose_print(f"Port:      {port}")
    verbose_print(f"Key:       {args.key_file}")
    verbose_print(f"Cert:      {args.cert_file}")
    verbose_print("\n", True)
    httpd = TCPServer((interface, port), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile=args.key_file,
        certfile=args.cert_file,
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
