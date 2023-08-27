#!/bin/bash
SCRIPT_PATH=$(dirname "$(realpath $0)")
certsArgs=("$@")
length=${#certsArgs[@]}
echo "current path: $SCRIPT_PATH"
echo "build：$length groups of certification files"

check_duplicates() {
    local list=("$@")

    # Creates an associative array to store the values in the list
    declare -A map
    for item in "${list[@]}"; do
        if [[ -n ${map[$item]} ]]; then
            echo "duplicate domain name: $item"
            exit 1
        fi
        map[$item]=""
    done

    echo "no duplicate domain name"
}

check_domain() {
    # regex matching string
    regex="^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"

    # check if arg name fits the regex expression
    if [[ $1 =~ $regex ]]; then
        echo "Domain name $1 is valid."
    else
        echo "Domain name $1 is invalid. Please rename it."
        exit 1
    fi
}

check_duplicates "${certsArgs[@]}"

for arg in "${certsArgs[@]}"
do
  check_domain $arg
done

mkdir certs
cd certs
openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout RootCA.key -out RootCA.pem -subj "/C=US/CN=DirectCommunication-Root-CA"

openssl x509 -outform pem -in RootCA.pem -out RootCA.crt

# Use loops to create folders and generate files in them
for ((i=0; i<length; i++))
do
  argnName=${certsArgs[i]}
  folder_name="$argnName"
  echo "building$i th certification group to $SCRIPT_PATH/certs/$folder_name for domain name: $argnName"
  domain_file_name="domains.txt"
  mkdir $folder_name
  cd $folder_name
  echo "authorityKeyIdentifier=keyid,issuer" > $domain_file_name
  echo "basicConstraints=CA:FALSE" >> $domain_file_name
  echo "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment" >> $domain_file_name
  echo "subjectAltName = @alt_names" >> $domain_file_name
  echo "[alt_names]" >> $domain_file_name
  echo "DNS.1 = $argnName" >> $domain_file_name

  openssl req -new -nodes -newkey rsa:2048 -keyout $argnName.key -out $argnName.csr -subj "/C=US/ST=Beijing/L=Haidian/O=DirectCommunication-Certificates/CN=localhost.local"
  openssl x509 -req -sha256 -days 1024 -in $argnName.csr -CA ../RootCA.pem -CAkey ../RootCA.key -CAcreateserial -extfile $domain_file_name -out $argnName.crt
  cd ..
done
