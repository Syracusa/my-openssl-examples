# my-openssl-examples

## Chaincert test
+ Test TLS/DTLS with 2-or-3 depth certificate. (Set USE_DTLS flag at CMakeLists.txt to DTLS test) 
+ Script that generate chained certificate(check ./cert/ directory).

## Simple examples

### ECDSA - src/ecdsa.c
+ ECDSA sign/verify example. 

### ECDH - src/ecdh.c
+ ECDH example.
+ Option for using hardcoded pre-generated key or newly generated one.

### HMAC - src/hmac.c
+ HMAC generate/verify example.