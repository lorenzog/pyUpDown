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
import shutil
import sys
from tempfile import TemporaryFile, NamedTemporaryFile
if sys.version_info.major >= 3:
    from http.server import SimpleHTTPRequestHandler, HTTPServer, CGIHTTPRequestHandler
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
    # encoded = b''.join(chr(ord(c) ^ ord(k)) for c, k in zip (what, cycle(key)))
    encoded_chars = []
    for c, k in zip(what, cycle(bytearray(key, 'utf-8'))):
        # both 'c' and 'k' are integers if the file is read with 'b'
        # log.debug("c: {} {}".format(c, type(c)))
        # log.debug("k: {} {}".format(k, type(k)))
        xor = c ^ k
        # log.debug(chr(xor))
        encoded_chars.append(chr(xor))
    log.debug("Encoded: {} {}".format(type(encoded_chars), repr(encoded_chars)))
    return ''.join(encoded_chars)


# class Handler(SimpleHTTPRequestHandler):
class Handler(CGIHTTPRequestHandler):
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
                self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
                # defaults to text/plain
                self.send_header("Content-type", mime)

                # encode
                if key is not None:
                    # TODO read in chunks and write to self.wfile?
                    encoded = encode(key, f.read())
                    encoded_b64 = base64.b64encode(bytearray(encoded, 'utf-8'))
                    # log.debug("b64 {} len: {}".format(encoded_b64, len(encoded_b64)))
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

    # test with: 
    # multipart/form-data: curl http://localhost:8080/upload' -F upload=@test.txt
    # application/x-www-form-urlencoded: curl http://localhost:8080/upload' -d @test.txt
    def do_POST(self):
        # TODO if not found, bail out
        _ct = self.headers.get('content-type')
        print("content-type: {}".format(_ct))
        import re
        _bound = dict(re.findall(r'(\S+)=(".*?"|\S+)', _ct))
        print("boundary: {}".format(repr(_bound.get('boundary'))))
        cgip = cgi.parse_header(_ct)
        print("cgip: {}".format(cgip))
        # TODO if exists
        if cgip[0].lower() == 'application/x-www-form-urlencoded':
            print("Form urlencoded, do later")
        elif cgip[0].lower() == 'multipart/form-data':
            print("Multipart form data")
        else:
            print("Nope")
            return

        # TODO make into functions, yadda yadda

        # # XXX tried to read from file directly, no luck
        # # mp = cgi.parse_multipart(self.rfile, cgip[1])

        # boundary_dict = {'boundary': bytes(cgip[1]['boundary'], 'ascii')}
        # # trying with a temporary file?
        # # XXX nope. locks before parse_multipart
        # tmp = NamedTemporaryFile(delete=False)
        # shutil.copyfileobj(self.rfile, tmp)
        # tmp.seek(0)
        # # mp = cgi.parse_multipart(self.rfile, boundary_dict)
        # mp = cgi.parse_multipart(tmp, boundary_dict)
        # print("Yea")
        # # mp = cgi.parse_multipart(self.rfile, _bound.get(str('boundary')))
        # # mp = cgi.parse_multipart(self.rfile, str(_ct))
        # # XXX
        # # trying to make sense of https://github.com/python/cpython/blob/3.6/Lib/cgi.py
        # print(dir(mp))
        # print(repr(mp))
        # print(mp.items())
        # self.send_response(301)
        # self.send_header('Location', '/')
        # self.end_headers()
        # return

        # # figure it out later
        # if _ct is not None:
        #     _ct = _ct[0]
        # print("XXX reading: {}".format(self.rfile.read()))

        f = cgi.FieldStorage(
            fp=self.rfile, headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'}
            # environ=_env
        )

        print(dir(f))
        print("Name: {}".format(f.name))
        print("Fileanme: {}".format(f.filename))
        print("File: {}".format(f.file))
        print("Fp: {}".format(f.fp))
        print("HEaders: {}".format(f.headers))
        print("Value: {}".format(f.value))
        print("len: {}".format(f.length))
        # if it's multipart/form-data, it's a recursive upload.. CBA
        print("qs: {}".format(f.qs_on_post))
        print("Type: {}".format(f.type))
        uploads = f.getlist('upload')
        if len(uploads) > 0:
            for u in uploads:
                print("Upload: {}".format(repr(u)))

        # with open('/tmp/stuff', 'wb') as g:
        #     f.file.seek(0)
        #     shutil.copyfileobj(f.file, g)

        # ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
        # postvars = {}
        # try:
        #     if ctype == 'application/x-www-form-urlencoded':
        #         length = int(self.headers.get('content-length'))
        #         fields = cgi.parse_multipart(self.rfile, pdict)
        #         content = fields.get('message')
        #         print("Content: (len: {}) {}".format(length, content))
        #         # postvars = cgi.parse_qs(self.rfile.read(length),
        #         #         keep_blank_values=1)
        #         # assert postvars.get('foo', '') != ['simulate error']
        #     # body = 'Something'
        #     # self.send_response(200)
        #     # self.send_header("Content-type", "text")
        #     # self.send_header("Content-length", str(len(body)))
        #     # self.end_headers()
        #     # self.wfile.write(body)
        # except:
        #     self.send_error(500)
        #     raise

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
    print("[+] Server started, bound to {}:{}".format(ip, port))
    print("[*] use '?b64=1' in URL to encode as base64")
    print("[*] use '?key=xxx' in URL to XOR with key and encode as base64")
    print("[*] open /upload for a basic upload form")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[+] Bye")


if __name__ == '__main__':
    main()
