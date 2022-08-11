#!/usr/bin/env python3

#
# forked from https://github.com/MollardMichael/python-reverse-proxy
# Add a simple password authentication before starting proxying
#

from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import argparse, os, random, sys, requests

from socketserver import ThreadingMixIn
from threading import Thread, Lock

from bottle import Bottle, ServerAdapter, request, redirect

dest_hostname = 'localhost'
dest_port = 80
password = None

# Ideas from https://stackoverflow.com/questions/11282218/bottle-web-framework-how-to-stop
class LoginServer(ServerAdapter):
    server = None

    def run(self, handler):
        from wsgiref.simple_server import make_server
        self.server = make_server(self.host, self.port, handler, **self.options)
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

app = Bottle()

@app.route('/')
def login():
    return '''
        <form action="/" method="post">
            Password: <input name="password" type="password" />
            <input value="Login" type="submit" />
        </form>
    '''

login_server = LoginServer(port=8080)
signal_to_stop = Lock()

@app.route('/', method='POST')
def do_login():
    global password
    global signal_to_stop
    if str(request.forms.get('password')) == password:
        signal_to_stop.release()
        redirect('/')
    else:
        redirect('/')

def login_begin():
    app.run(server=login_server)

def login_stop():
    global signal_to_stop
    global login_server
    signal_to_stop.acquire()
    login_server.stop()

def merge_two_dicts(x, y):
    return x | y

def set_header():
    headers = {
        'Host': dest_hostname
    }

    return headers

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def do_HEAD(self):
        self.do_GET(body=False)
        return
        
    def do_GET(self, body=True):
        sent = False
        try:
            url = 'https://{}{}'.format(dest_hostname, self.path)
            req_header = self.parse_headers()

            #print(req_header)
            #print(url)
            resp = requests.get(url, headers=merge_two_dicts(req_header, set_header()), verify=False)
            sent = True

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
            return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def do_POST(self, body=True):
        sent = False
        try:
            url = 'https://{}{}'.format(dest_hostname, self.path)
            content_len = int(self.headers.getheader('content-length', 0))
            post_body = self.rfile.read(content_len)
            req_header = self.parse_headers()

            resp = requests.post(url, data=post_body, headers=merge_two_dicts(req_header, set_header()), verify=False)
            sent = True

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            if body:
                self.wfile.write(resp.content)
            return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def parse_headers(self):
        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        #print ('Response Header')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                #print (key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--local_port', dest='local_port', type=int, default=8080,
                        help='listen HTTP requests on specified port (default: 8080)')
    parser.add_argument('--dest_hostname', dest='dest_hostname', type=str, default='localhost',
                        help='serve HTTP requests to specified host (default: localhost)')
    parser.add_argument('--dest_port', dest='dest_port', type=int, default=80,
                        help='serve HTTP requests to specified port (default: 80)')
    parser.add_argument('--password', dest='password', type=str, default=None,
                        help='password to be given (default:None')
    args = parser.parse_args(argv)
    return args

def main(argv=sys.argv[1:]):
    global dest_hostname, dest_port, password, signal_to_stop, login_server
    args = parse_args(argv)
    dest_hostname = args.dest_hostname
    dest_port = args.dest_port
    if args.password != None:
        password = args.password
        signal_to_stop.acquire()
        Thread(target=login_begin).start()
        signal_to_stop.acquire()
        login_server.stop()
    print('http server is starting on port {} for {}:{}...'.format(args.local_port, args.dest_hostname, args.dest_port))
    server_address = ('127.0.0.1', args.local_port)
    httpd = ThreadingHTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')
    httpd.serve_forever()
    print('hello')

if __name__ == '__main__':
    main()
