
./gen-certs.sh ddpwuxrmp.uk
touch certs/bad/bad.crt
touch certs/bad/bad.key
cargo test
rm -rf certs
