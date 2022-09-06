from http.server import HTTPServer
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
