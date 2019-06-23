# pyUpDown
Basic HTTP(s) Web Server with upload and download.

This server is designed to:

 1. Run with no dependencies apart from standard Python libraries.
 2. Return every file as text/plain.
 3. If requested, return files base64-encoded (think `powershell
    -encodedCommand...`) or XOR'd with a key of your choice
 3. Allow for file upload

Its purpose is to aid in exfiltrating data during a penetration test
(use socat to run it over ssl - see below) and transfer scripts, commandlets
and binary data.

**WARNING** The server will bind on 0.0.0.0:8080 by default. Don't leave
it listening over the open internet unprotected.

## Quickstart

    chmod +x s.py
    ./s.py

Then:

    $ echo "hello" > test.txt
    $ curl 'http://localhost:8080/test.txt'
    hello

    # just base64-encode the result
    $ curl 'http://localhost:8080/test.txt?b64=1' 2> /dev/null | base64 -d 
    hello

    # XOR the file with the key '123' and base64-encode the result
    $ curl 'http://localhost:8080/test.txt?key=123'
    WVdfXV05

    # upload stuff from a web browser:
    # visit http://localhost:8080/upload

    # upload stuff from the command line
    $ curl 'http://localhost:8080/upload' -F upload=@file.txt

For more options:

    ./s.py -h

## SSL Support

To run the whole thing over SSL, use `socat`:

 1. Generate a certificate and a private key into the same file. Do this
    once:

        openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout cert.pem -out cert.pem -days 365

 2. Run the server and keep it running:

        ./s.py

 3. From a different shell, use `socat` to connect to the server:

        socat openssl-listen:8443,verify=0,cert=cert.pem,reuseaddr,fork tcp4:localhost:8080

 4. Connect to `https://localhost:8443`

For socat with letsencrypt:

```
socat openssl-listen:443,fork,verify=0,cert=/etc/letsencrypt/live/yourhost/cert.pem,key=/etc/letsencrypt/live/yourhost/privkey.pem,reuseaddr tcp4:localhost:8080
```

## Miscellanea

 Use the `-d` command-line flag for verbose debugging messages.
