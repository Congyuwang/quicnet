
./gen-certs.sh ddpwuxrmp.uk

# create bad certs
mkdir -p certs/bad
touch certs/bad/bad.crt
touch certs/bad/bad.key

# create concatenated cert
cat ./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.crt > ./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.pem
cat ./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.key >>  ./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.pem

cargo test
rm -rf certs
