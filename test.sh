
./gen-certs.sh ddpwuxrmp.uk

# create empty certs
mkdir -p certsempty/
touch certs/empty/empty.crt
touch certs/empty/empty.key

# create concatenated cert
cat ./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.crt > ./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.pem
cat ./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.key >>  ./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.pem

# rust tests
cargo test

rm -rf certs
