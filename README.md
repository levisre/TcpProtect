#TcpProtect#

##Description##

This is a small ruby class which acts as a wrapper of TCP connection between a client and server to ensure the security using Key Exchange and Encryption.

**NOTE**: The HTTP (WebAPI) version can be found at: https://github.com/levisre/KeyExchange.

##Requirement##

- Ruby >= `2.3.0`

- `openssl`

##How it works##

- The client starts connection by generating its own keypair using ECDH and sends the public key to a specified server.

- The server receives the public key from client, generates it own keypair, sends the public key back to the client. The public key to be sent is signed by its own RSA private key, the signature is attached on the very beginning of the data chunk.

- Client receives thte data chunk from server, extracts signature and public key, then uses it own RSA public key (as a pair of Server's RSA private key), to verify that the key is sent from server or not. If not, then immediately close connection.

- Now both server and client have each other' public key. They calculate the Shared Secret and use it as an encryption key.

- From now on, all the data being sent are encrypted by Shared secret, until the connection is closed.

- Any newly created connection will perform all steps above again.

##File contents##

`tcpprotect.rb`: Contains the main class `TCPProtect` which is used by both client and server.

`server.rb`: Simple TCP Server listens on port `2001`, accepts Key Exchange and bounces back the data received from client. Supports multi-client.

`client.rb`: Connects to server and establishes secure connection. Has a prompt to accept user input and show the server response.

`make_keypaair.rb`: Generates RSA keypair used for authentication and message signing.
