"""Loopback-only authenticated UI with an optional native desktop window."""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
import os
import subprocess
import platform
import threading
from urllib.parse import urlsplit
import webbrowser

from desktop.service import Service, ROOT


def start_authorization_agent():
    binary = Path('/usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1')
    if sys.platform != 'linux' or not binary.is_file():
        return None
    existing = subprocess.run(['pgrep', '-u', str(os.getuid()), '-f', 'polkit.*authentication-agent'],
                              capture_output=True, timeout=2)
    if existing.returncode == 0:
        return None
    return subprocess.Popen([str(binary)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def configure_native_window(window):
    """Use explicit GTK window controls rather than WSL's close-only default.

    Called synchronously by pywebview before_show on the GUI thread. GTK
    settings here affect this process, not the user's desktop preferences.
    """
    if sys.platform != 'linux':
        return
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    native = window.native
    if not isinstance(native, Gtk.Window):
        return
    Gtk.Settings.get_default().set_property('gtk-application-prefer-dark-theme', True)
    header = native.get_titlebar()
    if header is None:
        header = Gtk.HeaderBar()
        native.set_titlebar(header)
    if isinstance(header, Gtk.HeaderBar):
        header.set_title(window.title)
        header.set_show_close_button(True)
        header.set_decoration_layout(':minimize,maximize,close')
        header.show_all()


def make_server(service, port=0):
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        # Reuse browser connections instead of creating TCP events on every
        # dashboard poll. Every reply below has an explicit Content-Length.
        protocol_version = 'HTTP/1.1'
        disable_nagle_algorithm = True

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, *_):
            pass

        def reply(self, data, code=200, content_type='application/json'):
            payload = data if isinstance(data, bytes) else json.dumps(data, allow_nan=False).encode()
            try:
                self.send_response(code)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(payload)))
                if self.close_connection:
                    self.send_header('Connection', 'close')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(payload)
            except ConnectionError:
                # Closing the window during a poll is a normal disconnect.
                self.close_connection = True

        def authorized(self):
            expected_host = f'127.0.0.1:{self.server.server_port}'
            if self.headers.get('Host') != expected_host:
                self.close_connection = True
                self.reply({'error': 'Invalid host'}, 403)
                return False
            if not hmac.compare_digest(self.headers.get('X-Sentinel-Token', ''), token):
                self.close_connection = True
                self.reply({'error': 'Open the application from its launcher'}, 403)
                return False
            origin = self.headers.get('Origin')
            if origin and origin != f'http://{expected_host}':
                self.close_connection = True
                self.reply({'error': 'Invalid origin'}, 403)
                return False
            return True

        def do_GET(self):
            path = urlsplit(self.path).path
            if path.startswith('/api/'):
                if not self.authorized():
                    return
                if path == '/api/state':
                    self.reply(service.snapshot())
                elif path == '/api/history':
                    self.reply(service.history())
                elif path == '/api/protection':
                    self.reply(service.protection_state())
                else:
                    self.reply({'error': 'Not found'}, 404)
                return
            assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                      '/app.css': ('app.css', 'text/css'), '/app.js': ('app.js', 'text/javascript'),
                      '/icon.svg': ('icon.svg', 'image/svg+xml')}
            if path not in assets:
                self.reply({'error': 'Not found'}, 404)
                return
            filename, content_type = assets[path]
            self.reply((ROOT / 'desktop/web' / filename).read_bytes(), content_type=content_type)

        def do_POST(self):
            if not self.authorized():
                return
            try:
                if self.headers.get('Transfer-Encoding'):
                    self.close_connection = True
                    raise ValueError('Transfer encoding is unsupported')
                length = int(self.headers.get('Content-Length', 0))
                if length < 0 or length > 1024:
                    self.close_connection = True
                    raise ValueError('Request too large')
                body = json.loads(self.rfile.read(length) or b'{}')
                if not isinstance(body, dict):
                    raise ValueError('Request must be a JSON object')
                if self.path == '/api/start':
                    speed = {'fast': .08, 'realtime': service.detector.seconds}[body.get('speed', 'fast')]
                    service.start(body.get('mode'), speed)
                    self.reply({'ok': True})
                elif self.path == '/api/stop':
                    service.stop()
                    self.reply({'ok': True})
                elif self.path == '/api/export':
                    self.reply(service.export_report())
                elif self.path == '/api/open-reports':
                    self.reply(service.open_reports_folder())
                elif self.path == '/api/test-alert':
                    self.reply(service.test_alert())
                elif self.path == '/api/scan':
                    service.scanner.start(body.get('path'))
                    self.reply({'ok': True})
                elif self.path == '/api/scan-stop':
                    service.scanner.stop()
                    self.reply({'ok': True})
                else:
                    self.reply({'error': 'Not found'}, 404)
            except (ValueError, KeyError, TypeError, OSError) as exc:
                self.close_connection = True
                self.reply({'error': str(exc)}, 400)

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    return server, token


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', action='store_true', help='Use a browser instead of a native window (WSL/headless fallback)')
    parser.add_argument('--no-open', action='store_true', help='Print the local address without opening a window')
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    service = Service()
    server, token = make_server(service, args.port)
    url = f'http://127.0.0.1:{server.server_port}/#token={token}'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print('Sentinel local application: ' + url, flush=True)
    auth_agent = None
    try:
        if not args.browser and not args.no_open:
            import webview
            if 'microsoft' not in platform.release().lower():
                auth_agent = start_authorization_agent()
            webview.settings['ALLOW_DOWNLOADS'] = True
            window = webview.create_window('Sentinel · Behavioral Detection', url, width=1280, height=850,
                                           min_size=(850, 600), background_color='#0d1010', text_select=True)
            window.events.before_show += configure_native_window
            from desktop.alerts import native_popup
            service.alert_popup = lambda title, message: native_popup(window, title, message)
            webview.start()
        else:
            if not args.no_open:
                webbrowser.open(url)
            thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        service.close()
        if auth_agent and auth_agent.poll() is None:
            auth_agent.terminate()
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
