#!/usr/bin/env python3
import argparse
import base64
import cgi
import cgitb
import io
from itertools import cycle
from socketserver import ForkingMixIn
import logging
import os
import random
import re
import ssl
import shutil
import string
import sys
import tempfile
if sys.version_info.major >= 3:
    from http.server import SimpleHTTPRequestHandler, HTTPServer
    from http import HTTPStatus
    from urllib.parse import urlparse, parse_qs
else:
    raise SystemExit("Run via python3")

# logging?
cgitb.enable()

log = logging.getLogger(__name__)
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter())
log.addHandler(sh)
log.setLevel(logging.INFO)


UPLOAD_FORM = b'''
<!doctype html>
<title>Upload new File</title>
<h1>Upload new File</h1>
<form method=post enctype=multipart/form-data>
<!-- <form method=post enctype=application/x-www-form-urlencoded> -->
<p><input type=file name=upload>
<input type=submit value=Upload>
</form>
'''

# defaults as globals
CORS = None
MIME = 'text/plain'
HEADERS = True
AUTH_KEY = None

TRY_BINARY = False


def encode(key, what):
    # inspired by
    # https://dustri.org/b/elegant-xor-encryption-in-python.html
    # encoded = b''.join(
    #   chr(ord(c) ^ ord(k)) for c, k in zip (what, cycle(key)))
    encoded_chars = []
    for c, k in zip(what, cycle(bytearray(key, 'utf-8'))):
        # both 'c' and 'k' are integers if the file is read with 'b'
        # log.debug("c: {} {}".format(c, type(c)))
        # log.debug("k: {} {}".format(k, type(k)))
        xor = c ^ k
        # log.debug(chr(xor))
        encoded_chars.append(chr(xor))
    log.debug("Encoded: {} {}".format(
        type(encoded_chars), repr(encoded_chars)))
    return ''.join(encoded_chars)


def handle_auth(handler):
    h = handler.headers.get("Authorization")
    if h is None:
        # no auth header
        return None
    log.debug("Matching {}".format(h))
    m = re.match(r'^Basic (.+)$', h)
    if m is None:
        # invalid auth header
        return None
    auth_string = m.group(1)
    if auth_string == '':
        # no auth
        return False
    try:
        decoded = base64.b64decode(auth_string)
        log.debug("auth: {}".format(decoded))
    except TypeError:
        log.error("Invalid b64")
        return False
    log.debug("Expected: {}".format(repr(AUTH_KEY)))
    if decoded != AUTH_KEY:
        return False
    return True


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # auth first
        if AUTH_KEY is not None:
            is_auth = handle_auth(self)
            if is_auth is False:
                log.debug("Wrong auth")
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                return
            elif is_auth is None:
                log.debug("No auth")
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                return
            else:
                log.debug("Auth OK")

        if HEADERS:
            log.info(self.requestline)
            log.info(self.headers)
        # get query and path
        try:
            u = urlparse(self.path)
            path = u.path

            query = parse_qs(u.query)

            key = query.get('key')
            if key is not None:
                key = key[0]
                log.debug("Encoding with: {}".format(key))

            # override mime default, if present in query
            _mime = query.get('mime')
            if _mime is not None:
                log.debug("Overriding MIME type with: {}".format(
                    _mime[0]))
                self.mime = _mime[0]
            else:
                # using global value
                self.mime = MIME

            # CORS
            _cors = query.get('cors')
            if _cors is not None:
                log.debug("Overriding CORS with: {}".format(
                    _cors[0]))
                self.cors = _cors[0]
            else:
                self.cors = CORS

            b64 = True if query.get('b64') is not None else False
            log.debug("Base64: {}".format(b64))

        except ValueError as e:
            log.error("Cannot parse URL: {}".format(e))
            # fallback to the path as supplied
            path = self.path

        log.debug("Path: {}".format(path))
        if path.endswith('/upload'):
            self.send_response(HTTPStatus.OK)
            # self.send_header("Content-type", "text/html")
            self.send_header("Content-type", self.mime)
            self.send_header("Content-length", len(UPLOAD_FORM))
            if self.cors is not None:
                log.debug("Setting Access-Control-Allow-Origin "
                          "header to: {}".format(self.cors))
                self.send_header("Access-Control-Allow-Origin", self.cors)
            self.end_headers()
            stuff = io.BytesIO()
            stuff.write(UPLOAD_FORM)
            stuff.seek(0)
            shutil.copyfileobj(stuff, self.wfile)
            return
        else:
            what = self.translate_path(path)

        stuff = None
        if os.path.isdir(what):
            stuff = self.list_directory(what)
            if stuff is not None:
                shutil.copyfileobj(stuff, self.wfile)
            return

        try:
            with open(what, 'rb') as f:
                fs = os.fstat(f.fileno())
                self.send_response(HTTPStatus.OK)
                self.send_header(
                    "Last-Modified",
                    self.date_time_string(fs.st_mtime))
                # defaults to text/plain
                self.send_header("Content-type", self.mime)
                if self.cors is not None:
                    log.debug("Setting Access-Control-Allow-Origin "
                              "header to: {}".format(self.cors))
                    self.send_header("Access-Control-Allow-Origin", self.cors)

                # encode
                if key is not None:
                    # TODO read in chunks and write to self.wfile?
                    encoded = encode(key, f.read())
                    encoded_b64 = base64.b64encode(bytearray(encoded, 'utf-8'))
                    tmp = tempfile.TemporaryFile()
                    tmp.write(encoded_b64)
                    self.send_header("Content-Length", str(len(encoded_b64)))
                    self.end_headers()
                    tmp.seek(0)
                    shutil.copyfileobj(tmp, self.wfile)
                    tmp.close()
                    return

                if b64 is True:
                    b64 = base64.b64encode(f.read())
                    tmp = tempfile.TemporaryFile()
                    tmp.write(b64)
                    self.send_header("Content-Length", str(len(b64)))
                    # log.debug("b64 {} len: {}".format(b64, len(b64)))
                    self.end_headers()
                    tmp.seek(0)
                    shutil.copyfileobj(tmp, self.wfile)
                    tmp.close()
                    return

                else:
                    self.send_header("Content-Length", str(fs[6]))
                    self.end_headers()
                    shutil.copyfileobj(f, self.wfile)
                    return

        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")

    def do_POST(self):
        f = cgi.FieldStorage(
            fp=self.rfile, headers=self.headers,
            # set to True otherwise curl -d @filename won't work
            keep_blank_values=True,
            # forcing the method otherwise it defaults to GET
            environ={'REQUEST_METHOD': 'POST'}
        )
        # now FieldStorage has parsed all the received uploads into the
        # 'value' field
        if len(f.value) == 0:
            print("[*] No content supplied")
            self.send_response(500)
            return
        for v in f.value:
            if isinstance(v, cgi.MiniFieldStorage):
                # this is for application/x-www-form-urlencoded
                # just get the 'name' parameter and value
                log.debug("Name: {}, Value: {}".format(v.name, repr(v.value)))
                if v.value is None or v.value == '':
                    log.debug("Blank value detected")
                    # only the name was provided, which is the actual data
                    fd, _name = tempfile.mkstemp(dir=os.getcwd())
                    # assuming utf-8 is ok
                    os.write(fd, bytearray(v.name, 'ascii'))
                    os.close(fd)
                else:
                    _name = os.path.basename(v.name)
                    while os.path.exists(_name):
                        print("[*] File exists, not overwriting")
                        _name += random.choice(string.digits)
                        log.debug("Trying {}".format(_name))
                    log.debug("Destination filename: {}".format(_name))
                    # open as 'w' not 'wb' as v.value is a string
                    try:
                        if TRY_BINARY is False:
                            # default: 'w' for this branch
                            _write_mode = 'w'
                        else:
                            # try 'wb'
                            _write_mode = 'wb'
                        with open(_name, _write_mode) as dst_file:
                            dst_file.write(v.value)
                    except TypeError as e:
                        print(e)
                        print(
                            "if error is TypeError: write() argument "
                            "must be str, not bytes\n"
                            " then try with the --binary command-line"
                            " parameter")
                print("[*] Data written to {}".format(_name))

            elif isinstance(v, cgi.FieldStorage):
                # Accept every type of file and save it locally.
                #
                # If there are problems with the binary format, then
                # discriminte using v.type as shown below
                # this is for multipart/form-data
                # if v.type.lower() == 'application/octet-stream':
                # ... write content with open(_name, 'wb')
                # elif v.type.lower() == 'text/plain':
                # ... write content with open(_name, 'w')

                if v.filename is None:
                    # make random name
                    _name = tempfile.mktemp(dir=os.getcwd())
                else:
                    _name = os.path.basename(v.filename)
                log.debug("Trying {}".format(_name))
                while os.path.exists(_name):
                    print("[*] File exists, not overwriting")
                    # this is a bit weird, re-uploading the same
                    # file results in the same random digits?
                    _name += random.choice(string.digits)
                    log.debug("Now trying {}".format(_name))
                log.debug("Destination filename: {}".format(_name))
                try:
                    if TRY_BINARY is False:
                        # default: 'wb' for this branch
                        _write_mode = 'wb'
                    else:
                        # try 'w'
                        _write_mode = 'w'
                    with open(_name, 'wb') as dst_file:
                        shutil.copyfileobj(v.file, dst_file)
                except TypeError as e:
                    print(e)
                    print("if error is TypeError: write() argument "
                          "must be str, not bytes\n"
                          " then try with the --binary command-line"
                          " parameter")
                print("[*] Data written to {}".format(_name))
            else:
                print("Something wrong in parsing content")
                self.send_response(500)
                return
        print("All content parsed")

        self.send_response(301)
        self.send_header('Location', '/')
        self.end_headers()


# double inheritance, because reasons!
class ForkingHTTPServer(ForkingMixIn, HTTPServer):
    def finish_request(self, request, client_address):
        # avoid hanging
        request.settimeout(30)
        # "super" can not be used because BaseServer is not created from object
        HTTPServer.finish_request(self, request, client_address)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=8080)
    parser.add_argument('-b', '--bind-to', default='0.0.0.0')
    parser.add_argument('-c', '--cors', default=None,
                        help="Set the Access-Control-Allow-Origin HTTP header")
    parser.add_argument('-m', '--mime', default='text/html',
                        help="Set the MIME type (Content-Type header)")
    parser.add_argument('-a', '--auth',
                        help=("Enable HTTP Basic Authentication "
                              "(format: username:password)"))
    parser.add_argument('-s', '--ssl', action='store_true',
                        help='Enable SSL support')

    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('--binary', action='store_true',
                        help="Force binary file write")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    port = args.port
    ip = args.bind_to
    # httpd = HTTPServer((ip, port), Handler)
    # inspired by: https://stackoverflow.com/a/10259265
    httpd = ForkingHTTPServer((ip, port), Handler)

    if args.ssl:
        try:
            httpd.socket = ssl.wrap_socket(
                httpd.socket,
                certfile=args.ssl,
                server_side=True)
            log.info("SSL Support Enabled")
        except FileNotFoundError as e:
            log.error(str(e) + ": " + args.ssl)
            _err = ("\nTo generate a self-signed certificate, "
                    "use\nopenssl req -x509 -newkey rsa:2048 "
                    "-nodes -subj \"/CN=localhost\" -keyout "
                    "cert.pem -out cert.pem -days 365\n")
            raise SystemExit(_err)

    # set defaults as globals, cuz of the double inheritance above it's a PITA
    # to set them as object properties
    if args.cors is not None:
        log.debug("Setting default CORS to: {}".format(args.cors))
        global CORS
        CORS = args.cors
    if args.mime is not None:
        global MIME
        MIME = args.mime
    if args.auth is not None:
        repr(args.auth)
        global AUTH_KEY
        print("[+] Setting authentication: {}".format(args.auth))
        AUTH_KEY = bytes(args.auth, 'utf-8')
    if args.binary is True:
        global TRY_BINARY
        TRY_BINARY = True
        print("[+] Forcing binary file write")

    print("[*] use '?b64=1' in URL to encode as base64")
    print("[*] use '?key=xxx' in URL to XOR with key and encode as base64")
    print("[*] use '?cors=xxx' to set the Access-Control-Allow-Origin header")
    print("[*] use '?mime=xxx' in URL to download a file with "
          "a specific mime type (e.g. application/octet-stream). "
          "Default: {}".format(MIME))
    print("[*] Uploads:")
    print("    open /upload for a basic upload form in a web browser")
    print("    or use: curl -u username:pass http://..../upload -F "
          "upload=@file")
    print("    or use: curl -u username:pass http://..../upload -d "
          "key=val")
    print("[+] Server started, bound to {}:{}".format(ip, port))
    print("[+] Press CTRL-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[+] Bye")


if __name__ == '__main__':
    main()
