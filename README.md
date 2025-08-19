# Combined QUIC and TLS Server

This is the source code for Combined QUIC+TLS Server. This combined server can handle both TLS as well as QUIC clients simultaneously. The server also caches a user connection details so that on next connection, the client can connect and be served faster.

# Description

Traditional TLS over TCP ensures strong security but suffers from latency due to connection establishment and head-of-line blocking. QUIC, on the other hand, offers multiplexed streams and faster handshakes (0-RTT) but is relatively new and lacks widespread compatibility with legacy systems. To leverage the advantages of both protocols, a combined QUIC and TLS server was implemented. This server provides secure, low-latency communication through QUIC while maintaining fallback support for conventional TLS clients, ensuring broader compatibility and improved performance in real-world deployments. The system was evaluated by measuring both connection establishment time and client request serving latency on first connection as well as on connection re-establishment, demonstrating QUIC’s performance benefits over traditional TLS.

## Getting Started

### Dependencies

* C
* OpenSSL 3.5 or greater

### Executing program
* Navigate to the path of the server and client files
* Create the certificate
```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.pem -days 365 \
  -subj "/CN=localhost"
```
* Compile the c program files
Replace $OPENSSL_ROOT with the path of lib folder from openSSL 3.5 installation.
```
gcc combined_server.c -o combined_server -I$OPENSSL_ROOT/include
-L$OPENSSL_ROOT/lib -lssl -lcrypto
gcc tls_client.c -o tls_client -I$OPENSSL_ROOT/include
-L$OPENSSL_ROOT/lib -lssl -lcrypto
gcc quic_client.c -o quic_client -I$OPENSSL_ROOT/include
-L$OPENSSL_ROOT/lib -lssl -lcrypto
```
* Run the server
```
./combined_server
```
* Run the clients on 2 seperate terminals

```
./tls_client
```
```
./quic_client
```

## Version History

* 1.0
    * Initial Release


