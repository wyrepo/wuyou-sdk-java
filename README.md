# wuyou-sdk-go

A simple SDK for Fabric(v2.2.0), contains a gateway of Fabric and some cryptography tools.

gateway of Fabric(v2.2.0):
* work with configuration easily
* connect to Fabric easily
* invoke a chaincode easily

cryptography tools:
* SM2: key generation, encrypt/decrypt, sign/verify (like RSA)
* SM3: calculate digest of a message (like SHA256)
* SM4: key generation, encrypt/decrypt (like AES)
* Paillier: key generation, addCipherText/subCipherText, addPlainText/mulPlainText/divPlainText

## config

How to config crypto files (if you have org4, see the example below):
* copy "ordererOrganizations" and "peerOrganizations" of Fabric network
* paste "ordererOrganizations" and "peerOrganizations" to "crypto" in this project
* check files in "ordererOrganizations/example.com", there should be
  - "/msp/tlscacerts/tlsca.example.com-cert.pem"
  - "/users/User1@org4.example.com/msp/keystore/key.pem"   (rename it to key.pem)
  - "/users/User1@org4.example.com/msp/signcerts/cert.pem" (rename it to cert.pem)
* check files in "peerOrganizations/org4.example.com", there should be
  - "/tlsca/tlsca.org4.example.com-cert.pem"
  - "/users/Admin@example.com/msp/keystore/key.pem"   (rename it to key.pem)
  - "/users/Admin@example.com/msp/signcerts/cert.pem" (rename it to cert.pem)
* delete unused files in "ordererOrganizations" and "peerOrganizations"

How to config project yaml (if you have org4):
* open config.yaml in this project
* pay attention to "Org4"
* modify the values if necessary

```
-- crypto
   |-- ordererOrganizations
       |-- example.com
           |-- msp
               |-- tlscacerts
                   |-- tlsca.example.com-cert.pem
           |-- users
               |-- Admin@example.com
                   |-- msp
                       |-- keystore
                           |-- key.pem
                       |-- signcerts
                           |-- cert.pem
   |-- peerOrganizations
       |-- org4.example.com
           |-- tlsca
               |-- tlsca.org4.example.com-cert.pem
           |-- users
               |-- User1@org4.example.com
                   |-- msp
                       |-- keystore
                           |-- key.pem
                       |-- signcerts
                           |-- cert.pem
```
