# simpleWebServer

Expanding on pythons Simple HTTP Server to include HTTPS

## Installing

Right now the module can be installed by cloning this repo and then installing
it with pip.

    git clone https://github.com/samfelt/simpleWebServer
    cd simpleWebServer
    pip install .

## Running

After installation, running the HTTPS server is as simple as:

    python3 -m https.server

## Generating a certificate

When the server is run for the first time, it will ask if you would like to
generate a certificate to be used. If you say yes, a self-signed certificate
will be generated and stored in the `https/certs/` directory. This certificate
will be be used every time the server is started after that.

If you ever want to regenerate certificate, start the server with a the
`--generate` switch. This will automatically generate a new certificate and
replace the oold one in `https/certs/`.
