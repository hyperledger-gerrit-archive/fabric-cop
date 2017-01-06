# COP

COP is the name for Membership Services in v1.0 of Hyperledger Fabric.
COP is not an acronym.  The name "COP" was selected because of the following.

  * COP provides police-like security functionality for Hyperledger Fabric.  It is the "fabric COP";
  * COP is shorter and easier to say and write than “Membership Services v1.0” :-)

See the [COP design doc](https://docs.google.com/document/d/1TRYHcaT8yMn8MZlDtreqzkDcXx0WI50AV2JpAcvAM5w)
for information on what COP will provide.

<div id='contents'>
# Table of Contents
1. [Topology](#topology)
2. [Getting Started](#getting-started)
	1. [Prequisites](#prerequisites)
	2. [Explore the COP CLI](#explore)
	3. [Development vs Production](#devprod)
3. [Create CSR.json](#csr)
4. [Initialize the COP Server](#initialize)
5. [TLS/SSL Configuration](#tls)
	1. [Client & COP Server](#tls-client-server)
	2. [Database & COP Server](#tls-db-server)
6. [COP Server Configuration Properties](#configuration)
7. [Start the COP server](#start)
8. [Enroll the admin client](#enroll)
9. [Reenroll](#reenroll)
10. [Register a new user](#register)
11. [Revoke a user](#revoke)
12. [LDAP](#ldap)
13. [Setting up a cluster](#cluster)
	1. [HAProxy](#haproxy)
	1. [PostgreSQL](#postgres)
	2. [MySQL](#mysql)
14. [Run the cop tests](#tests)
15. [Appendix](#appendix)

<div id='topology'/>
## Topology

![COP Topology](cop.png)

[Back to Top](#contents)

<div id='getting-started'/>
## Getting Started

<div id='prerequisites'/>
### Prerequisites

* Go 1.6+ installation or later
* **GOPATH** environment variable is set correctly
* **COP** environment variable is set to **$GOPATH/src/github.com/hyperledger/fabric-cop**

<div id='installation'/>
### Installation

#### Docker

Run the following commands to set up a docker container running a cop server.
Navigate to `$COP` and execute `make docker`.

After previous command completes, to launch the COP server, run the following:

```
# docker run hyperledger/fabric-cop
```

Open up a new terminal window and run:

```
# docker ps
```

Get the id of the container that was launched with the docker run command.
The container id will be needed for the next command.

```
# docker exec -it <container-id> sh
```

At this point you should be inside the container and can execute cop commands.

#### Go Install

```
# go get -u github.com/hyperledger/fabric-cop
```

will download the COP server, installing it in `$GOPATH/github.com/hyperledger/fabric-cop`.
Navigate to `$COP` and execute `make cop`. This will build the COP executable
(i.e. the 'COP' binary). The executable is located at `$COP/bin/cop`.

<div id='explore'/>
### Explore the COP CLI

The following shows the COP usage message:


```
# cd $COP/bin
# ./cop
cop client       - client related commands
cop server       - server related commands
cop cfssl        - all cfssl commands

For help, type "cop client", "cop server", or "cop cfssl".
```

The COP client and server commands are what you will use.
However, since COP is built on top of [CFSSL](https://github.com/cloudflare/cfssl)
and CFSSL has its own CLI, you may issue any cfssl command with the `cop cfssl`
command prefix.

Refer to table for more information on specific commands. Refer to CFSSL
documentation on specific commands available for CFSSL.


| Component  | Command  | Description                                             | Usage                                                     |
|------------|----------|---------------------------------------------------------|-----------------------------------------------------------|
| **Client** | enroll   | Enroll a user                                           | cop client enroll ID SECRET COP-SERVER-URL                |
|            | reenroll | Reenroll a user                                         | cop client reenroll COP-SERVER-URL                        |
|            | register | Register an ID and get an enrollment secret             | cop client register REGISTER-REQUEST-FILE COP-SERVER-URL  |
|            | revoke   | Revokes one or more certificates                        | revoke COP-SERVER-URL [ENROLLMENT_ID]                     |
| **Server** | init     | Generates a new private key and self-signed certificate | cop server init CSRJSON                                   |
|			       | start    | Start the COP server                                    | cop server start [-config CONFIG-FILE]                    |

<div id='devprod'>
### Develpment vs Production

#### Develpment
A development environment does not require much configuration. By default,
COP server uses SQLite database. This removes any requirement of having to set
up a database for development purposes. When starting COP server for the first
time, the COP server will create a SQLite database and then make use of it from
this point forward. However, SQLite has limitation such as its inability to
support remote connections. For that reason, SQLite is not recommended for use
in a production environment. See Production section below for more information.

#### Production
In production, a database that supports remote connection is required to allow
for clustering. PostgreSQL and MySQL are two database that COP server supports.
Refer to [Setting up a Cluster](#cluster) for more details on how to setup a
cluster environment.

LDAP can also be used in production, refer to [LDAP](#ldap) for instructions on setup.

[Back to Top](#contents)

<div id='csr'/>
## Create CSR.json

In order to generate a Certificate and Key, you must provide a JSON file
containing the relevant details of your request. This JSON file looks something
like:

```
{
    "hosts": [
        "example.com",
        "www.example.com"
    ],
    "CN": "www.example.com",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [{
        "C": "US",
        "L": "San Francisco",
        "O": "Example Company, LLC",
        "OU": "Operations",
        "ST": "California"
    }]
}
```

The `../testdata/csr_dsa.json` file can be customized to generate x509
certificates and keys that support both RSA and Elliptic Curve (ECDSA).

The following setting is an example of the implementation of Elliptic Curve
Digital Signature Algorithm (ECDSA) with curve:
secp384r1 and Signature Algorithm: ecdsa-with-SHA384:

"algo": "ecdsa"  
"size": 384

The choice of algorithm and key size are based on security needs.

Elliptic Curve (ECDSA) offers the following curves and security levels:

| size        | ASN1 OID           | Signature Algorithm  |
|-------------|:-------------:|:-----:|
| 256      | prime256v1 | ecdsa-with-SHA256 |
| 384      | secp384r1      |   ecdsa-with-SHA384 |
| 521 | secp521r1     | ecdsa-with-SHA512 |

Likewise, these are the secure choices for RSA modulus:

| size        | Modulus (bits)| Signature Algorithm  |
|-------------|:-------------:|:-----:|
| 2048      | 2048 | sha256WithRSAEncryption |
| 4096      | 4096 | sha512WithRSAEncryption |

See table below for more information on fiels in the CSR.json

|Field|Description|
|-----|-----------|
|hosts| List of the domain names which the certificate should be valid for|
|CN| Used by some CAs to determine which domain the certificate is to be generated for instead; these CAs will most often provide a certificate for both the "www" (e.g. www.example.net) and "bare" (e.g. example.net) domain names if the "www" domain name is provided|
|key| Key generation protocol|
|names| "C": country<br>"L": locality or municipality (such as city or town name)<br>"O": organisation<br>"OU": organisational unit, such as the department responsible for owning the key; it can also be used for a "Doing Business As" (DBS) name<br>"ST": the state or province|
<div id='initialize'/>

[Back to Top](#contents)

## Initialize the COP server  

Executing the following "COP" command will generate a private key and self-signed
x509 certificate to start the COP server in the [Start the COP server](#start) section.
These two PEM files will be generated and stored in the directory
`$COP_HOME/.cop/`: server-cert.pem and server-key.pem.
They can be used as input parameters to `-ca` and `-ca-key` in the command to
start the COP server.

```
# cd $COP/bin
# ./cop server init ../testdata/csr_dsa.json
```

[Back to Top](#contents)

<div id='tls'/>
## TLS/SSL Configuration
<div id='tls-client-server'/>

### Generating TLS Certificate and Key
By default, COP server is setup to use TLS when communicating with client. If no specific TLS Certificate and Key
is specified it will default to using the CA Certificate and Key which is required to start up a COP server
([Starting the COP server](#start))

However, if a different TLS Certificate and Key would like to be used, they can
be generated using the instructions in [Initialize the COP server](#initialize)
to generate a pair that can be used for TLS purposes.

### Client & COP Server

The steps below should be followed to enable a secure connection between client
and server.

1. The COP server should be started with the following properties set in the COP
configuration file (cop.json). The **tls_cert** and **tls_key** point to the certificate
and key that would like to be used for setting up the TLS protocol. The
**mutual_tls\_ca** property requires that client certificates be signed by this specific
CA and client is required to send its certificate. The configuration file for
the server should contain the following:

```
"tls_cert":"tls_certificate.pem",
"tls_key":"tls_key.pem",
"mutual_tls_ca":"CA_root_cert.pem",
```

2. On client side, a configuration file (cop\_client.json) should be created as
seen below and placed in the client home directory (see [Cop Directory](#directory)).
The **ca\_certfiles** option is the set of root certificates that client uses when
verifying server certificates. The **client** option contains file paths to
certificate and key to present to the other side of the connection.

```
{
"ca_certfiles":["CA_root_cert.pem"],
"client":[{"keyfile":"client-key.pem","certfile":"client.pem"}]
}
```

Once all the certificates and key have been properly configured on both client
and server a secure connection should be established.

<div id='tls-db-server'/>
### Database & COP Server
#### PostgreSQL

When specifying the connection string for the PostgreSQL database in the server
configuration file (cop.json), we must indicate that we wish to use a secure connection.
The connection string should be set as indicated below.

```
"driver":"postgres",
"data_source":"host=localhost port=5432 user=Username password=Password dbname=cop sslmode=verify-full",
```
**sslmode** - Enable SSL.

  - **verify-full** - Always SSL (verify that the certification presented by the
    PostgreSQL server was signed by a trusted CA and the PostgreSQL server host name
     matches the one in the certificate).

We also need to set the TLS configuration in the COP server config file. If the
database server requires client authentication than a client cert and key file
needs to be provided. The following should be present in the COP server config:

```
"tls":{
  ...
  "db_client":{
    "ca_certfiles":["CA_root_cert.pem"],
    "client":{"keyfile":"client-key.pem","certfile":"client-cert.pem"}
  }
},
```

**ca_certfiles** - The location of the root certificate file.

**certfile** - Client certificate file.

**keyfile** - Client key file.

### MySQL

When specifying the connection string for the MySQL database in the server
configuration file, we must indicate that we wish to use a secure connection.
The connection string should be set with the **tls=custom** parameter as
indicated below.

```
"driver":"mysql",
"data_source":"root:rootpw@tcp(localhost:3306)/cop?parseTime=true&tls=custom",
```

In the configuration file for the COP server, we need to define the properties
below to establish a secure connection between COP server and MySQL server. If
the database server requires client authentication than a client cert and key
file needs to be provided as well.

```
"tls":{
  ...
  "db_client":{
    "ca_certfiles":["CA_root_cert.pem"],
    "client":{"keyfile":"client-key.pem","certfile":"client-cert.pem"}
  }
},
```

**ca_certfiles** - The location of the root certificate file.

**certfile** - Client certificate file.

**keyfile** - Client key file.

[Back to Top](#contents)

<div id='configuration'/>
## COP Server Configuration

|Property        |              Description                                                                                    |
|----------------|-------------------------------------------------------------------------------------------------------------|
|tls_disable     | Disable TLS Connection (default=false)                                                                      |
|driver          | Specify database type, 3 options available: sqlite3, postgres, mysql                                        |
|data_source     | Connection information for connecting to database. See specific database sections for more info             |
|max_enrollments | Number of enrollments allowed for registered users (default=unlimited)                                      |
|ca_cert         | File path to CA certificate on file system                                                                  |
|ca_key          | File path to CA key on file system                                                                          |
|tls_cert        | File path to the TLS certificate on file system                                                             |
|tls_key         | File path to the TLS key on file system                                                                     |
|mutual_tls\_ca  | File path to certificate that Client certificate should be signed by                                        |
|ca_certfiles    | File path to root certificate of which database certificate is signed by                                    |
|keyfile         | File path to DB client key on file system                                                                   |
|certfile        | File path to DB client certificate on file system                                                           |
|users           | Defines users that server will be bootstrapped with. See ./testdata/cop.json for example on defining users  |
|groups          | Defines groups that server will be bootstrapped with. See ./testdata/cop.json for example on defining groups|


[Back to Top](#contents)

<div id='start'/>
## Start the COP server

Execute the following commands to start the COP server.  If you would like to
specify debug-level logging, set the `COP_DEBUG` environment variable to `true`.
And if you would like to run this in the background, append the "&" character to
the command.

In cop.json, specify the following properties. They specify the file to where
the CA certificate and CA key are stored.

```
"ca_cert":"cop-cert.pem",
"ca_key":"cop-key.pem",
```

Run the following command to start COP server:

```
# cd $COP/bin
# ./cop server start -config ../testdata/cop.json
```

It is now listening on localhost port 8888.

You can customize your COP config file at `../testdata/cop.json`.  For example,
if you want to disable authentication, you can do so by setting `authentication` to
`false`.  This prevents the COP server from looking at the authorization header.
Auhentication is added by COP since CFSSL does not perform authentication.  A standard HTTP
basic authentication header is required for the enroll request.  All other requests
to the COP server will require a JWT-like token, but this work is not yet complete.

[Back to Top](#contents)

<div id='enroll'/>
## Enroll the admin client

See the `$COP/testdata/cop.json` file and note the "admin" user with a password of "adminpw".
The following command gets an ecert for the admin user.

```
# cd $COP/bin
# ./cop client enroll admin adminpw https://localhost:8888
```

The enrollment certificate is stored at `$COP_ENROLLMENT_DIR/cert.pem` by default,
but a different path can be specified by setting the `COP_CERT_FILE` environment
variable to an absolute path name or a path relative to the current working directory.

The enrollment key is stored at `$COP_ENROLLMENT_DIR/key.pem` by default, but a
different path can be specified by setting the `COP_KEY_FILE` environment
variable to an absolute path name or a path relative to the current working directory.

The default value of the `COP_ENROLLMENT_DIR` environment variable is `$COP_HOME`.

The default value of the `COP_HOME` environment variable is `$HOME/.cop`.

[Back to Top](#contents)

<div id='reenroll'/>
## Reenroll

Suppose your enrollment certificate is about to expire.  You can issue the
reenroll command to renew your enrollment certificate as follows.  Note that
this is identical to the enroll command except no username or password is
required.  Instead, your previously stored private key is used to authenticate
to the COP server.

```
# cd $COP/bin
# ./cop client reenroll ../testdata/csr.json https://localhost:8888
```

The enrollment certificate and enrollment key are stored in the same location as
described in the previous section for the `enroll` command.

[Back to Top](#contents)

<div id='register'/>
## Register a new user

The user performing the registeration request must be currently enrolled, and also
this registrar must have the proper authority to register the type of user being
registered. The registrar must have been enrolled with attribute
"hf.Registrar.DelegateRoles". The DelegateRoles attribute specifies the types
this registrar is allowed to register.

For example, the attributes for a registrar might look like this:

```
"attrs": [{"name":"hf.Registrar.DelegateRoles", "value":"client,user"}]

```

The registrar should then create a JSON file as defined below for the user being
registered.

registerrequest.json:

```
{
  "id": "User1",
  "type": "client",
  "group": "bank_a",
  "attrs": [{"name":"AttributeName","value":"AttributeValue"}]
}
```

The following command will register the user and return a password. The password can
then be used to enroll.

```
# cd $COP/bin
# ./cop client register ../testdata/registerrequest.json https://localhost:8888
```

[Back to Top](#contents)

<div id='revoke'>
## Revoke certificates

To revoke a specific certificate, AKI and Serial number for the certificate needs
to be provided.

```
# cd $COP/bin
# ./cop client revoke https://localhost:8888 -aki 1234 -serial 1234
```

To revoke a user, an Enrollment ID must be provided.

```
# cd $COP/bin
# ./cop client revoke https://localhost:8888 user1
```

[Back to Top](#contents)

<div id='ldap'/>
## LDAP

The COP server can be configured to read from an LDAP server.

In particular, the COP server may connect to an LDAP server to do the following:

   * authenticate a user prior to enrollment, and   
   * retrieve a user's attribute values which is used for authorization.

In order to configure the COP server to connect to an LDAP server, add a section
of the following form to your COP server's configuration file:

```
{
   "ldap": {
       "url": "scheme://adminDN:pass@host[:port][/base]"
       "userfilter": "filter"
   }
```

where:  
   * `scheme` is one of *ldap* or *ldaps*;  
   * `adminDN` is the distinquished name of the admin user;  
   * `pass` is the password of the admin user;   
   * `host` is the hostname or IP address of the LDAP server;  
   * `port` is the optional port number, where default 389 for *ldap* and 636 for *ldaps*;  
   * `base` is the optional root of the LDAP tree to use for searches;  
   * `filter` is a filter to use when searching to convert a login user name to
   a distinquished name.  For example, a value of `(uid=%s)` searches for LDAP
   entries with the value of a `uid` attribute whose value is the login user name.
   Similarly, `(email=%s)` may be used to login with an email address.

The following is a sample configuration section for the default settings for the
 OpenLDAP server whose docker image is at `https://github.com/osixia/docker-openldap`.

```
 "ldap": {
    "url": "ldap://cn=admin,dc=example,dc=org:admin@localhost:10389/dc=example,dc=org",
    "userfilter": "(uid=%s)"
 },
```

See `COP/testdata/testconfig-ldap.json` for the complete configuration file with
this section.  Also see `COP/scripts/run-ldap-tests` for a script which starts
an OpenLDAP docker image, configures it, runs the LDAP tests in
COP/cli/server/ldap/ldap_test.go, and stops the OpenLDAP server.

#### When LDAP is configured, enrollment works as follows:

  * A COP client or client SDK sends an enrollment request with a basic
  authorization header.
  * The COP server receives the enrollment request, decodes the user/pass in the
  authorization header, looks up the DN (Distinquished Name) associated with the
  user using the "userfilter" from the configuration file, and then attempts an
  LDAP bind with the user's password. If successful, the enrollment processing
  is authorized and can proceed.

#### When LDAP is configured, attribute retrieval works as follows:

   * A client SDK sends a request for a batch of tcerts **with one or more attributes**
   to the COP server.  
   * The COP server receives the tcert request and does as follows:
       * extracts the enrollment ID from the token in the authorization header
       (after validating the token);
       * does an LDAP search/query to the LDAP server, requesting all of the
       attribute names received in the tcert request;
       * the attribute values are placed in the tcert as normal

[Back to Top](#contents)

<div id='cluster'/>
## Setting up a cluster

<div id='haproxy'>
### HAProxy
First step to support clustering is setting up a proxy server. HAProxy is used
in this example. Below is a basic configuration file that can be used to get
HAProxy up and running. Change hostname and port to reflect the settings of your
COP servers.

haproxy.conf

```
global
      maxconn 4096
      daemon

defaults
      mode http
      maxconn 2000
      timeout connect 5000
      timeout client 50000
      timeout server 50000

listen http-in
      bind *:8888
      balance roundrobin
      server server1 <hostname:port>
      server server2 <hostname:port>
      server server3 <hostname:port>
```

<div id='postgres'/>
### PostgreSQL

When starting up the COP servers specify the database that you would like to
connect to. In your COP configuration file, the following should be present for
a PostgreSQL database:

cop.json

```
...
"driver":"postgres",
"data_source":"host=localhost port=5432 user=Username password=Password dbname=cop",
...
```

Change "host" and "dbname" to reflect where your database is located and the
database you would like to connect to. Default port is used if none is specified.
Enter username and password for a user that has permission to connect to the
database.

Once your proxy, COP servers, and PostgreSQL server are all running you can have
your client direct traffic to the proxy server which will load balance and direct
traffic to the appropriate COP server which will read/write from the PostgreSQL
database.  

<div id='mysql'/>
### MySQL

When starting up the COP servers specify the database that you would like to
connect to. In your COP configuration file, the following should be present for
a PostgreSQL database:

cop.json

```
...
"driver":"mysql",
"data_source":"root:rootpw@tcp(localhost:3306)/cop?parseTime=true&tls=custom",
...
```

Change the host to reflect where your database is located. Change "root" and
"rootpw" to the username and password you would like to use to connec to the
database. The database is specified after the '/', specify the database you
would like to connect to. Default port is used if none is specified.

Once your proxy, COP servers, and database servers are all running you can have
your clients direct traffic to the proxy server which will load balance and
direct traffic to the appropriate COP server which will read/write from the
database.  

[Back to Top](#contents)

<div id='tests'/>
## Run the cop tests

To run the COP test, do the following.

WARNING: You must first stop the COP server which you started above; otherwise,
it will fail with a port binding error.

```
# cd $COP
# make unit-tests
```

[Back to Top](#contents)

<div id='appendix'/>
## Appendix

### PostgreSQL SSL Configuration

**Basic instructions for configuring SSL on PostgreSQL server:**
1. In postgresql.conf, uncomment SSL and set to "on" (SSL=on)
2. Place Certificate and Key files in Postgres data directory.

Instructions for generating self-signed certificates for:
https://www.postgresql.org/docs/9.1/static/ssl-tcp.html

Note: Self-signed certificates are for testing purposes and should not be used
in a production environment

**PostgreSQL Server - Require Certificates from COP server**
1. Place certificates of the certificate authorities (CAs) you trust in the file
 root.crt in the PostgreSQL data directory
2. In postgresql.conf, set "ssl_ca_file" to point to the root cert of client (CA cert)
3. Set the clientcert parameter to 1 on the appropriate hostssl line(s) in pg_hba.conf.

For more details on configuring SSL on the PostgreSQL server, please refer to the
following PostgreSQL documentation: https://www.postgresql.org/docs/9.4/static/libpq-ssl.html


### MySQL SSL Configuration
**Basic instructions for configuring SSL on MySQL server:**
1. Open or create my.cnf file for the server. Add or un-comment the lines below
in [mysqld] section. These should point to the key and certificates for the
server, and the root CA cert.

Instruction on creating server and client side certs:
http://dev.mysql.com/doc/refman/5.7/en/creating-ssl-files-using-openssl.html

[mysqld]
ssl-ca=ca-cert.pem
ssl-cert=server-cert.pem
ssl-key=server-key.pem

Can run the following query to confirm SSL has been enabled.

mysql> SHOW GLOBAL VARIABLES LIKE 'have_%ssl';

Should see:
```
+---------------+-------+
| Variable_name | Value |
+---------------+-------+
| have_openssl  | YES   |
| have_ssl      | YES   |
+---------------+-------+
```

2. After the server-side SSL configuration is finished, the next step is to
create a user who has a privilege to access the MySQL server over SSL. For that,
log in to the MySQL server, and type:

mysql> GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%' IDENTIFIED BY 'password' REQUIRE SSL;
mysql> FLUSH PRIVILEGES;

If you want to give a specific ip address from which the user will access the
server change the '%' to the specific ip address.

**MySQL Server - Require Certificates from COP server**
Options for secure connections are similar to those used on the server side.

- ssl-ca identifies the Certificate Authority (CA) certificate. This option,
if used, must specify the same certificate used by the server.
- ssl-cert identifies the client public key certificate.
- ssl-key identifies the client private key.

Suppose that you want to connect using an account that has no special encryption
requirements or was created using a GRANT statement that includes the REQUIRE SSL
option. As a recommended set of secure-connection options, start the MySQL
server with at least --ssl-cert and --ssl-key, and invoke the COP server with
**ca_certfiles** option set in the COP server file.

To require that a client certificate also be specified, create the account using
the REQUIRE X509 option. Then the client must also specify the proper client key
and certificate files or the MySQL server will reject the connection. CA cert,
client cert, and client key are all required for the COP server.

<div id='directory'>
### COP Directory
The COP directory will contain various files depending on if server or client side.

Location of COP directory will depend on the environment variables set. If
COP\_HOME is set, the cop directory can be found at $COP\_HOME/fabric-cop.
If COP\_HOME is not and HOME is set than the cop directory can be found at
$HOME/fabric-cop.

[Back to Top](#contents)
