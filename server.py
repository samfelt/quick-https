from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer


def main():
    interface = 'localhost'
    port = 8080
    httpd = TCPServer((interface, port), SimpleHTTPRequestHandler)
    try:
        print(f"Serving HTTP on {interface}, port {port}...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nRecieved Keyboard Interupt... Shutting Down")
        httpd.server_close()


if __name__ == '__main__':
    main()
