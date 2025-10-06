#!/bin/bash

openssl s_client -connect localhost:8443 \
  -servername localhost \
  -cert    pki/client/client-fullchain.crt \
  -key     pki/client/client.key \
  -CAfile  pki/ca_server/ca.crt \
  -prexit -brief
