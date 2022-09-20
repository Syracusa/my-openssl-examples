./clean.sh

touch index.txt
echo 01 > serial
echo 1000 > crlnumber


# Generate RootCA Key
echo '###############################'
echo '##### Generate RootCA Key #####'
echo '###############################'
# (RSA) openssl genrsa -out private/cakey.pem 1024
openssl ecparam -out private/cakey.pem -name prime256v1 -genkey

# Generate RootCA Cert
echo '################################'
echo '##### Generate RootCA Cert #####'
echo '################################'
printf '\n\n\n\n\nRootCA\n\n' | \
openssl req -new -x509 -days 3650 -key private/cakey.pem -out certs/ca.cert.pem -config rootca.cnf -extensions v3_ca

# Verify RootCA Cert
echo '##############################'
echo '##### Verify RootCA Cert #####'
echo '##############################'
openssl x509 -text -noout -in certs/ca.cert.pem



# Generate ICA Key
echo '############################'
echo '##### Generate ICA Key #####'
echo '############################'
# (RSA) openssl genrsa -out private/icakey.pem 1024
openssl ecparam -out private/icakey.pem -name prime256v1 -genkey

# Generate ICA CSR
echo '############################'
echo '##### Generate ICA CSR #####'
echo '############################'
printf '\n\n\n\n\nICA\n\n' | \
openssl req -new -sha256 -key private/icakey.pem -out csr/ica.cert.csr.pem -config ica.cnf

# Generate ICA Cert
echo '#############################'
echo '##### Generate ICA Cert #####'
echo '#############################'
printf 'y\ny\n' | \
openssl ca -in csr/ica.cert.csr.pem -days 3650 -out certs/ica.cert.pem -config ica.cnf -extensions v3_intermediate_ca

# Verify ICA Cert
echo '###########################'
echo '##### Verify ICA Cert #####'
echo '###########################'
openssl x509 -noout -text -in certs/ica.cert.pem
openssl verify -verbose -CAfile certs/ca.cert.pem certs/ica.cert.pem



# Concatenate RootCA Cert with ICA Cert
echo '#################################################'
echo '##### Concatenate RootCA Cert with ICA Cert #####'
echo '#################################################'
cat certs/ica.cert.pem certs/ca.cert.pem > certs/ca-chain-bundle.cert.pem

echo '####################################'
echo '##### Verify Concatenated Cert #####'
echo '####################################'
openssl verify -verbose -CAfile certs/ca.cert.pem certs/ca-chain-bundle.cert.pem



# Generate Server Key
echo '###############################'
echo '##### Generate Server Key #####'
echo '###############################'
# (RSA) openssl genrsa -out private/server.pem 1024
openssl ecparam -out private/server.pem -name prime256v1 -genkey

# Generate Server CSR
echo '###############################'
echo '##### Generate Server CSR #####'
echo '###############################'
printf '\n\n\n\n\nServer\n\n\n\n' | \
openssl req -new -sha256 -key private/server.pem -out csr/server.csr.pem

# Generate Server Cert
echo '################################'
echo '##### Generate Server Cert #####'
echo '################################'
openssl x509 -req -in csr/server.csr.pem -CA certs/ca-chain-bundle.cert.pem -CAkey private/icakey.pem -out certs/server.cert.pem -CAcreateserial -days 3650 -sha256 -extfile server.cnf
# openssl ca -cert certs/ca-chain-bundle.cert.pem -in csr/server.csr.pem -out certs/server.cert.pem -days 3650 -config ica.cnf -extfile server.cnf

# Verify Server Cert
echo '##############################'
echo '##### Verify Server Cert #####'
echo '##############################'
openssl x509 -noout -text -in certs/server.cert.pem
openssl verify -verbose -CAfile certs/ca-chain-bundle.cert.pem certs/server.cert.pem



# Generate Client Key
echo '###############################'
echo '##### Generate Client Key #####'
echo '###############################'
# (RSA) openssl genrsa -out private/cakey.pem 1024
openssl ecparam -out private/client.pem -name prime256v1 -genkey

# Generate Client CSR
echo '###############################'
echo '##### Generate Client CSR #####'
echo '###############################'
printf '\n\n\n\n\nClient\n\n\n\n' | \
openssl req -new -sha256 -key private/client.pem -out csr/client.csr.pem

# Generate Client Cert
echo '################################'
echo '##### Generate Client Cert #####'
echo '################################'
openssl x509 -req -in csr/client.csr.pem -CA certs/ca-chain-bundle.cert.pem -CAkey private/icakey.pem -out certs/client.cert.pem -CAcreateserial -days 3650 -sha256 -extfile client.cnf
# openssl ca -cert certs/ca-chain-bundle.cert.pem -in csr/client.csr.pem -out certs/client.cert.pem -days 3650 -config ica.cnf -extfile client.cnf

# Verify Client Cert
echo '##############################'
echo '##### Verify Client Cert #####'
echo '##############################'
openssl x509 -noout -text -in certs/client.cert.pem
openssl verify -verbose -CAfile certs/ca-chain-bundle.cert.pem certs/client.cert.pem

cp certs/* ..
cp private/client.pem ..
cp private/server.pem ..
