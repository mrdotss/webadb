import subprocess
import os
import re
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
from urllib.parse import urlparse
from argparse import ArgumentParser

cli = ArgumentParser(description='Web ADB -- a simple server for monitoring Android devices')
cli.add_argument('-p', '--port', type=int, dest='port', default=8080)
cli.add_argument('--cert-file', dest='certfile')
cli.add_argument('--adb-path', dest='adbpath', default=os.environ.get('WEB_ADB'))
arguments = cli.parse_args()

def adb(args, device=None):
    base = [arguments.adbpath]
    if device is not None:
        base = base + ['-s', device]

    args = base + args
    p = subprocess.Popen([str(arg) for arg in args], stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)

def _getprop(device, property, default):
    (rc, out, _) = adb(['shell', 'getprop', property], device=device)
    if not rc == 0:
        return default
    elif out.strip():
        return out.strip()
    else:
        return default

def getPull(device, source, destination):
    (rc, out, err) = adb(['pull', source, destination], device=device)
    adb(['pull', source, destination], device=device)
    
    if rc != 0:
        print(err)
    else:
        print("pull success!")

def _getnetwork(device):
    (rc, out, err) = adb(["shell", "dumpsys wifi | grep 'current SSID' | grep -o '{.*}'"], device=device)
    ore = out
    ore = ore.decode("utf-8")
    ore = ore.replace('=', ':')
    ore = ore.replace('iface', '"iface"')
    ore = ore.replace('"iface":', '"iface":"')
    ore = ore.replace(',ssid', '","ssid"')
    oreDict = json.loads(ore)

    print('network done ' + str(rc))
    if rc != 0:
        print(err)

    network = {
        'connected': True,
        'ssid': oreDict['ssid']
    }

    for l in out.split('\n'.encode("utf-8")):
        tokens = l.split()
        if not len(tokens) > 10 or tokens[0] != 'mNetworkInfo':
            continue
        print("Token 4:", tokens[4])
        print("Token 8:", tokens[8])
        network['connected'] = (tokens[4].startswith('CONNECTED/CONNECTED'.encode("utf-8")))
        network['ssid'] = tokens[8].replace('"'.encode("utf-8"), ''.encode("utf-8")).rstrip(','.encode("utf-8"))

    return network

def _getbattery(device):
    (rc, out, err) = adb(['shell', 'dumpsys', 'battery'], device=device)
    print('battery done ' + str(rc))
    if rc != 0:
        print(err)

    battery = {
        'plugged': 0,
        'level': 0,
        'status': 1,
        'health': 1
    }

    for l in out.split('\n'.encode("utf-8")):
        tokens = l.split(': '.encode("utf-8"))
        if len(tokens) < 2:
            continue

        key = tokens[0].strip().lower()
        value = tokens[1].strip().lower()
        if key.decode('utf-8') == 'ac powered' and value == 'true':
            battery['plugged'] = 'AC'
        elif key.decode('utf-8') == 'usb powered' and value == 'true':
            battery['plugged'] = 'USB'
        elif key.decode('utf-8') == 'wireless powered' and value == 'true':
            battery['plugged'] = 'Wireless'
        elif key.decode('utf-8') == 'level':
            battery['level'] = value
        elif key.decode('utf-8') == 'status':
            battery['status'] = value
        elif key.decode('utf-8') == 'health':
            battery['health'] = value
    print(battery)
    return battery

def _getscreen(device):
    (rc, out, err) = adb(['shell', 'dumpsys', 'input'], device=device)
    # print('screen done ' + str(rc))
    if rc != 0:
        print(err)

    screen = {
        'width': 0,
        'height': 0,
        'orientation': 0,
        'density': 0
    }

    for l in out.split('\n'.encode("utf-8")):
        tokens = l.split(': '.encode("utf-8"))
        if len(tokens) < 2:
            continue
        key = tokens[0].strip().lower()
        value = tokens[1].strip().lower()

        if key.decode('utf-8') == 'surfacewidth':
            screen['width'] = value
        elif key.decode('utf-8') == 'surfaceheight':
            screen['height'] = value
        elif key.decode('utf-8') == 'surfaceorientation':
            screen['orientation'] = value
    (rc, out, err) = adb(['shell', 'wm', 'density'], device=device)
    tokens = out.split(': '.encode("utf-8"))
    if len(tokens) == 2:
        screen['density'] = tokens[1].strip()

    return screen

def get_devices(handler):
    (_, out, _) = adb(['devices'])

    devices = []
    for l in out.split('\n'.encode("utf-8")):
        tokens = l.split()
        if not len(tokens) == 2:
            # Discard line that doesn't contain device information
            continue

        id = tokens[0].decode('utf-8')
        devices.append({
            'id': id,
            'manufacturer': _getprop(id, 'ro.product.manufacturer', 'unknown'),
            'model': _getprop(id, 'ro.product.model', 'unknown'),
            'sdk': _getprop(id, 'ro.build.version.sdk', 'unknown'),
            'network': _getnetwork(id),
            'battery': _getbattery(id),
            'screen': _getscreen(id)
        })
    return devices

def get_screenshot(handler):
    path = urlparse(handler.path).path
    device = path[12:]
    print(device)
    (rc, out, err) = adb(['exec-out', 'screencap', '-p'], device=device)
    print('screencap done ' + str(rc))
    if rc != 0:
        print(err)
    return out

def get_logcat(handler):
    path = urlparse(handler.path).path
    device = path[8:]
    print(device)
    (rc, out, err) = adb(['logcat', '-d', '-v', 'brief'], device=device)
    print('logcat done ' + str(rc))
    if rc != 0:
        print(err)
    return out

def get_info(handler):
    path = urlparse(handler.path).path
    device = path[9:]
    print(device)

    info = {
        'id': device,
        'manufacturer': _getprop(id, 'ro.product.manufacturer', 'unknown'),
        'model': _getprop(id, 'ro.product.model', 'unknown'),
        'sdk': _getprop(id, 'ro.build.version.sdk', 'unknown'),
        'network': _getnetwork(device),
        'battery': _getbattery(device),
        'screen': _getscreen(device)
    }
    return info

def post_key(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'key' in payload:
        device = payload['device']
        key = payload['key']
        print(device + ' : ' + str(key))
        (rc, _, err) = adb(['shell', 'input', 'keyevent', key], device=device)
        print('keyevent done ' + str(rc))
        if rc != 0:
            print(err)
    return 'OK'

def post_text(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'text' in payload:
        device = payload['device']
        text = payload['text']
        text = text.replace(' ', '%s')
        print(device + ' : ' + str(text))
        (rc, _, err) = adb(['shell', 'input', 'text', '"' + text + '"'], device=device)
        print('text done ' + str(rc))
        if rc != 0:
            print(err)
    return 'OK'

def post_tap(handler):
    payload = handler.get_payload()
    if 'device' in payload and 'x' in payload and 'y' in payload:
        device = payload['device']
        x = payload['x']
        y = payload['y']
        print(device + ' : ' + str(x) + ', ' + str(y))
        (rc, _, err) = adb(['shell', 'input', 'tap', x, y], device=device)
        print('tap done ' + str(rc))
        if rc != 0:
            print(err)
    return 'OK'

def post_shell(handler):
    rc, out, err = None, None, None
    payload = handler.get_payload()
    if 'device' in payload and 'command' in payload:
        device = payload['device']
        command = payload['command']
        print(device + ' : ' + command)
        (rc, out, err) = adb(['shell', command], device=device)
        print('shell done ' + str(rc))
        if rc != 0:
            print(err)
    return out

def post_reboot(handler):
    payload = handler.get_payload()
    if 'device' in payload:
        device = payload['device']
        print(device)
        (rc, _, err) = adb(['reboot'], device=device)
        print('reboot done ' + str(rc))
        if rc != 0:
            print(err)
    return 'OK'

class RESTRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.routes = {
            r'^/$': {'file': 'web/index.html', 'media_type': 'text/html'},
            r'^/devices$': {'GET': get_devices, 'media_type': 'application/json'},
            r'^/screenshot': {'GET': get_screenshot, 'media_type': 'image/png', 'cache_type': 'no-cache, no-store, must-revalidate'},
            r'^/logcat': {'GET': get_logcat, 'media_type': 'text/plain'},
            r'^/info': {'GET': get_info, 'media_type': 'application/json'},
            r'^/key$': {'POST': post_key, 'media_type': 'text/plain'},
            r'^/text$': {'POST': post_text, 'media_type': 'text/plain'},
            r'^/tap$': {'POST': post_tap, 'media_type': 'text/plain'},
            r'^/shell$': {'POST': post_shell, 'media_type': 'text/plain'},
            r'^/reboot$': {'POST': post_reboot, 'media_type': 'text/plain'}
        }
        
        return BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
    
    def do_HEAD(self):
        self.handle_method('HEAD')
    
    def do_GET(self):
        self.handle_method('GET')

    def do_POST(self):
        self.handle_method('POST')

    def do_PUT(self):
        self.handle_method('PUT')

    def do_DELETE(self):
        self.handle_method('DELETE')
    
    def get_payload(self):
        payload_len = int(self.headers.get('content-length', 0))
        # payload_len = int(self.headers.get_content_charset(0))
        payload = self.rfile.read(payload_len)
        payload = json.loads(payload)
        return payload
        
    def handle_method(self, method):
        route = self.get_route()
        if route is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write('Route not found\n'.encode("utf-8"))
        else:
            if method == 'HEAD':
                self.send_response(200)
                if 'media_type' in route:
                    self.send_header('Content-type', route['media_type'])
                self.end_headers()
            else:
                if 'file' in route and method == 'GET':
                    try:
                        here = os.path.dirname(os.path.realpath(__file__))
                        f = open(os.path.join(here, route['file']))
                        try:
                            self.send_response(200)
                            if 'media_type' in route:
                                self.send_header('Content-type', route['media_type'])
                            self.end_headers()
                            self.wfile.write(f.read().encode("utf-8"))
                        finally:
                            f.close()
                    except:
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write('File not found\n'.encode("utf-8"))
                else:
                    if method in route:
                        content = route[method](self)
                        if content is not None:
                            self.send_response(200)
                            if 'media_type' in route:
                                self.send_header('Content-type', route['media_type'])
                            if 'cache_type' in route:
                                self.send_header('Cache-control', route['cache_type'])
                            self.end_headers()
                            if method != 'DELETE':
                                if route['media_type'] == 'application/json':

                                    # Change some value from bytes to string (original)
                                    content[0]['manufacturer'] = content[0]['manufacturer'].decode('utf-8')
                                    content[0]['model'] = content[0]['model'].decode('utf-8')
                                    content[0]['sdk'] = content[0]['sdk'].decode('utf-8')
                                    content[0]['battery']['level'] = content[0]['battery']['level'].decode('utf-8')
                                    content[0]['battery']['status'] = content[0]['battery']['status'].decode('utf-8')
                                    content[0]['battery']['health'] = content[0]['battery']['health'].decode('utf-8')
                                    self.wfile.write(json.dumps(content).encode('utf-8'))
                                else:
                                    self.wfile.write(content)
                        else:
                            self.send_response(404)
                            self.end_headers()
                            self.wfile.write('Not found\n'.encode("utf-8"))
                    else:
                        self.send_response(405)
                        self.end_headers()
                        self.wfile.write(method + ' is not supported\n')
                        
    def get_route(self):
        for path, route in self.routes.items():
            if re.match(path, self.path):
                return route
        return None

def rest_server(port):
    http_server = HTTPServer(('', port), RESTRequestHandler)
    if arguments.certfile:
        http_server.socket = ssl.wrap_socket(http_server.socket, certfile=arguments.certfile, server_side=True)

    print('Starting HTTP server at port %d' % port)

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass

    print('Stopping HTTP server')
    http_server.server_close()

if __name__ == '__main__':
    rest_server(arguments.port)