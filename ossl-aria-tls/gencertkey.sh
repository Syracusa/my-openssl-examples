openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out server_cert.pem -keyout server_key.pem
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out client_cert.pem -keyout client_key.pem
