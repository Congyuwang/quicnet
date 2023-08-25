#!/bin/bash
SCRIPT_PATH=$(dirname "$(realpath $0)")
certsNum=$1
echo "当前脚本路径: $SCRIPT_PATH"
echo "构建：$certsNum 组证书"

#cd /root
openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout RootCA.key -out RootCA.pem -subj "/C=US/CN=DirectCommunication-Root-CA"

openssl x509 -outform pem -in RootCA.pem -out RootCA.crt

# 使用循环创建文件夹并在其中生成文件
for ((i=1; i<=certsNum; i++))
do
  folder_name="cert_$i"
  echo "构建第$i 组证书到$SCRIPT_PATH/$folder_name"
  domain_file_name="domains_$i.txt"
  mkdir $folder_name
  cd $folder_name
  echo "authorityKeyIdentifier=keyid,issuer" > $domain_file_name
  echo "basicConstraints=CA:FALSE" >> $domain_file_name
  echo "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment" >> $domain_file_name
  echo "subjectAltName = @alt_names" >> $domain_file_name
  echo "[alt_names]" >> $domain_file_name
  echo "DNS.1 = direct-node-$i" >> $domain_file_name
  cp ../RootCA.key RootCA.key
  cp ../RootCA.pem RootCA.pem
  cp ../RootCA.crt RootCA.crt
  openssl req -new -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.csr -subj "/C=US/ST=Beijing/L=Haidian/O=DirectCommunication-Certificates/CN=localhost.local"
  openssl x509 -req -sha256 -days 1024 -in localhost.csr -CA RootCA.pem -CAkey RootCA.key -CAcreateserial -extfile $domain_file_name -out localhost.crt
  cd ..
done

