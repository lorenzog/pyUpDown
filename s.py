#!/usr/bin/env python3
import argparse
import os
import shutil
from http.server import SimpleHTTPRequestHandler, HTTPServer
from http import HTTPStatus


PAGE = b'''
<!doctype html>
<title>Upload new File</title>
<h1>Upload new File</h1>
<form method=post enctype=multipart/form-data>
<p><input type=file name=file>
<input type=submit value=Upload>
</form>
'''

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith('/upload'):
            stuff = io.BytesIO()
            stuff.write(UPLOAD_FORM)
            stuff.seek(0)
        else:
            what = self.translate_path(self.path)

        stuff = None
        if os.path.isdir(what):
            stuff = self.list_directory(what)
            if stuff is not None:
                shutil.copyfileobj(stuff, self.wfile)
            return

        try:
            with open(what, 'rb') as f:
                # f = open(path, 'rb')
                fs = os.fstat(f.fileno())
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(fs[6]))
                self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
                # force text/plain
                self.send_header("Content-type", "text/plain")
                # or: self.guess_type(path)
                self.end_headers()
                shutil.copyfileobj(f, self.wfile)

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
    parser.add_argument('port', type=int)
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
