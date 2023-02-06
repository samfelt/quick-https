from http.server import SimpleHTTPRequestHandler


class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    """
    Extend the SimpleHTTPHander to add some functionality:
      * Handle post requests to receive  files to the server
      * Provide a link or button on the normal page to upload of a file
    """

    def __init__(self, request, client_address, server):
        SimpleHTTPRequestHandler.__init__(
            self, request, client_address, server
        )

    def do_POST(self):
        self.send_response(200)
