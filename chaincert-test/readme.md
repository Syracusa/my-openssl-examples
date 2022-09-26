# Dtls-chaincert
 + DTLS Connection test application
 + Use certificate chain(rootca-ica-server/client)

# Build
 + pushd cert/generate
 + ./generate.sh
 + popd
 + mkdir build
 + cd build
 + cmake ..
 + make