#!/usr/bin/env python3
import argparse
import base64
import io
import os
import shutil
import sys
from itertools import cycle
from tempfile import TemporaryFile
if sys.version_info.major >= 3:
    from http.server import SimpleHTTPRequestHandler, HTTPServer
    from http import HTTPStatus
    from urllib.parse import urlparse, parse_qs
else:
    raise SystemExit("Run via python3")


UPLOAD_FORM = b'''
<!doctype html>
<title>Upload new File</title>
<h1>Upload new File</h1>
<form method=post enctype=multipart/form-data>
<p><input type=file name=file>
<input type=submit value=Upload>
</form>
'''


def encode(key, what):
    # inspired by
    # https://dustri.org/b/elegant-xor-encryption-in-python.html
    # encoded = b''.join(chr(ord(c) ^ ord(k)) for c, k in zip (what, cycle(key)))
    encoded_chars = []
    for c, k in zip(what, cycle(bytearray(key, 'utf-8'))):
        # both 'c' and 'k' are integers if the file is read with 'b'
        print("c: {} {}".format(c, type(c)))
        print("k: {} {}".format(k, type(k)))
        xor = c ^ k
        print(chr(xor))
        encoded_chars.append(chr(xor))
    print("Encoded: {} {}".format(type(encoded_chars), repr(encoded_chars)))
    return ''.join(encoded_chars)


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # get query and path
        try:
            u = urlparse(self.path)
            query = parse_qs(u.query)
            # TODO get mime type?
            key = query.get('key')
            if key is not None:
                key = key[0]
                print("Encoding with: {}".format(key))
            mime = query.get('mime', 'text/plain')
            b64 = True if query.get('b64') is not None else False
            print("Base64: {}".format(b64))
            path = u.path
        except ValueError as e:
            print("Cannot parse URL: {}".format(e))
            path = self.path

        print("Path: {}".format(path))
        if path.endswith('/upload'):
            stuff = io.BytesIO()
            stuff.write(UPLOAD_FORM)
            stuff.seek(0)
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
                self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
                # defaults to text/plain
                self.send_header("Content-type", mime)

                # encode
                if key is not None:
                    # TODO read in chunks and write to self.wfile?
                    encoded = encode(key, f.read())
                    encoded_b64 = base64.b64encode(bytearray(encoded, 'utf-8'))
                    print("b64 {} len: {}".format(encoded_b64, len(encoded_b64)))
                    tmp = TemporaryFile()
                    tmp.write(encoded_b64)
                    self.send_header("Content-Length", str(len(encoded_b64)))
                    self.end_headers()
                    tmp.seek(0)
                    shutil.copyfileobj(tmp, self.wfile)
                    tmp.close()
                    return

                if b64 is True:
                    b64 = base64.b64encode(f.read())
                    tmp = TemporaryFile()
                    tmp.write(b64)
                    self.send_header("Content-Length", str(len(b64)))
                    print("b64 {} len: {}".format(b64, len(b64)))
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
        # self.headers
        # self.rfile.read(len)
        # self.wfile.write(stuff)
        print("This is a post")
        # return 301 to /
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=8080)
    parser.add_argument('-b', '--bind-to', default='0.0.0.0')
    args = parser.parse_args()

    port = args.port
    ip = args.bind_to
    httpd = HTTPServer((ip, port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Bye")


if __name__ == '__main__':
    main()
