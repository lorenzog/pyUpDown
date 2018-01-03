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


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # get query and path
        try:
            u = urlparse(self.path)
            path = u.path

            query = parse_qs(u.query)

            key = query.get('key')
            if key is not None:
                key = key[0]
                log.debug("Encoding with: {}".format(key))

            mime = query.get('mime')
            if mime is not None:
                mime = mime[0]
            else:
                mime = 'text/plain'

            b64 = True if query.get('b64') is not None else False
            log.debug("Base64: {}".format(b64))

        except ValueError as e:
            log.error("Cannot parse URL: {}".format(e))
            # fallback to the path as supplied
            path = self.path

        log.debug("Path: {}".format(path))
        if path.endswith('/upload'):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-length", len(UPLOAD_FORM))
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
                self.send_header("Content-type", mime)

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
                    os.write(fd, bytearray(v.name, 'utf-8'))
                    # isn't this a double open?
                    # with open(_name, 'w') as f:
                    #     f.write(v.name)
                    os.close(fd)
                else:
                    _name = os.path.basename(v.name)
                    while os.path.exists(_name):
                        print("[*] File exists, not overwriting")
                        _name += random.choice(string.digits)
                        log.debug("Trying {}".format(_name))
                    log.debug("Destination filename: {}".format(_name))
                    # open as 'w' not 'wb' as v.value is a string
                    with open(_name, 'w') as dst_file:
                        dst_file.write(v.value)
                print("[*] Data written to {}".format(_name))

            elif isinstance(v, cgi.FieldStorage):
                # this is for multipart/form-data
                # if v.type.lower() == 'application/octet-stream':
                log.debug("octet-stream detected")
                if v.filename is None:
                    # make random name
                    _name = tempfile.mktemp(dir=os.getcwd())
                else:
                    _name = os.path.basename(v.filename)
                log.debug("Trying {}".format(_name))
                while os.path.exists(_name):
                    print("[*] File exists, not overwriting")
                    _name += random.choice(string.digits)
                    log.debug("Now trying {}".format(_name))
                log.debug("Destination filename: {}".format(_name))
                with open(_name, 'wb') as dst_file:
                    shutil.copyfileobj(v.file, dst_file)
                print("[*] Data written to {}".format(_name))
                # elif v.type.lower() == 'text/plain':
                #     # TODO
                #     # same as before, but open('w') instead
                #     print("hehe")
                #     pass
                # else:
                #     print("Unrecognised content type: {}".format(v.type))
                #     self.send_response(500)
                #     return
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
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    port = args.port
    ip = args.bind_to
    # httpd = HTTPServer((ip, port), Handler)
    # inspired by: https://stackoverflow.com/a/10259265
    httpd = ForkingHTTPServer((ip, port), Handler)
    print("[*] use '?b64=1' in URL to encode as base64")
    print("[*] use '?key=xxx' in URL to XOR with key and encode as base64")
    print("[*] Uploads:")
    print("    open /upload for a basic upload form in a web browser")
    print("    or use: curl http://..../upload -F upload=@file")
    print("    or use: curl http://..../upload -d key=val")
    print("[+] Server started, bound to {}:{}".format(ip, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[+] Bye")


if __name__ == '__main__':
    main()
