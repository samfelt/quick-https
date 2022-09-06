from http.server import HTTPServer


class HTTPSServer(HTTPServer):
    """Extend HTTPServer to include HTTPS."""

    def __init__(self, address, handler, ssl_context):
        """Intialize the HTTPS server.
        Add a field for the ssl context to wrap the socket.
        """

        HTTPServer.__init__(self, address, handler)
        self.socket = ssl_context.wrap_socket(
            sock=self.socket,
            server_side=True,
            do_handshake_on_connect=True,
            suppress_ragged_eofs=True,
        )
