from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import ssl

def main():
    interface = 'localhost'
    port      = 8080
    with TCPServer((interface, port), SimpleHTTPRequestHandler) as httpd:
        print(f"Serving HTTP on {interface}, port {port}...")
        httpd.serve_forever()


if __name__ == '__main__':
    main()
