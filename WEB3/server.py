from http.server import HTTPServer, BaseHTTPRequestHandler

class Serv(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("ngrok-skip-browser-warning ", 1)
        self.end_headers()

httpd = HTTPServer(('localhost',8080),Serv)
httpd.serve_forever()
