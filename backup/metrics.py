import http.server

STATE_DIR = '/var/backup'


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path != '/metrics':
            self.send_response(404)
            self.end_headers()
            return

        try:
            ts = open(f'{STATE_DIR}/last_timestamp').read().strip()
        except OSError:
            ts = '0'
        try:
            sz = open(f'{STATE_DIR}/last_size').read().strip()
        except OSError:
            sz = '0'

        body = (
            '# HELP backup_last_timestamp_seconds Unix timestamp of last successful backup\n'
            '# TYPE backup_last_timestamp_seconds gauge\n'
            f'backup_last_timestamp_seconds {ts}\n'
            '# HELP backup_last_size_bytes Size in bytes of last backup file\n'
            '# TYPE backup_last_size_bytes gauge\n'
            f'backup_last_size_bytes {sz}\n'
        )

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
        self.end_headers()
        self.wfile.write(body.encode())


class DualStackServer(http.server.HTTPServer):
    address_family = __import__('socket').AF_INET6

    def server_bind(self):
        self.socket.setsockopt(__import__('socket').IPPROTO_IPV6, __import__('socket').IPV6_V6ONLY, 0)
        super().server_bind()


DualStackServer(('::', 9091), MetricsHandler).serve_forever()
