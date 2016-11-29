# To build a docker image with cop
```sh
$ docker build fabric-cop -t fabric-cop:latest
```

# Setup environment variables (optional)
If you want to use your own defined certificates, be sure to save these certificates in the /var/hyperledger/fabric/.cop directory in your environment. Then set the following environment variables accordingly.

```sh
$ export CA_CERTIFICATE=<public key pem file>      # default: ec.pem
$ export CA_KEY_CERTIFICATE=<private key pem file> # default: ec-key.pem
$ export COP_CONFIG=<COP configuration file>       # default: cop.json (contains users, database setup, groups, and signing information)
$ export CSR_CONFIG=<CSR configuration file>       # default: csr.json (contains the Certificate Signing Request config information)
```

# Certificate private and public files
Be sure to save the desired certificate files to the /var/hyperledger/fabric/.cop directory

You can also generate the certificates by running the following script that outputs server.pem and server-key.pem files and saves them to your $HOME/.cop directory.
```sh
$ cop server init /config/csr.json
```

# To execute the cop server and cop clients
```sh
$ docker-compose -f docker-compose-cop.yml up --force-recreate -d
```

