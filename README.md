# pyUpDown
Basic HTTP(s) Web Server with upload and download.

This server is designed to:

 1. Run with no dependencies apart from standard Python libraries.
 2. Return every file as text/plain.
 3. Allow for file upload [TODO]

Its purpose is to aid in exfiltrating data during a penetration test
(TODO: use socat to run it over ssl?) and transfer scripts, commandlets
and 

## Quickstart

    python3 s.py

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

