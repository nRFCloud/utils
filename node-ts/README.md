# ModeJS (Typescript) Utilities for Working with nRF Cloud

The main use of these scripts is with the [ProvisionDevices endpoint](https://api.nrfcloud.com/v1#operation/ProvisionDevices), which allows you to upload a CSV file containing one or more deviceIds and ES256 certificates in PEM format, created with your own CA certificate. These scripts demonstrate how you can programmatically generate a CA cert and corresponding device certificates that will work on nRF Cloud.

See the top of each file and the params in for example.

## CA Certificate Creator
```
--version                   Show version number [boolean]
--cnSubjectPrefix           The prefix for the cert Subject. [string] [required]
--ouName, --ou              The Organizational Unit (OU) name of the cert Subject. [string] [required]
--certFileNamePrefix, --fn  The prefix for the CA cert files. [string] [default: "ca-cert"]
--certDir, --cd             The absolute path to the directory to save the created cert files. 
                            [string] [default: "/path/to/utils/node-ts/certs"]
```

## Device Certificate Creator
```
  --deviceId                [string] [default: "4a28b11a-04b8-47e3-9632-df0e89159550"]
  --cnSubject               [string] [required] [default: "/C=NO/ST=Trondelag/L=Trondheim/O=Nordic Semiconductor ASA"]
  --caCertKeyPath           Name of your CA private key pem file [string] [default: "ca-cert.key.pem"]
  --caCertPemPath           Name of your CA certificate pem file [string] [default: "ca-cert.crt.pem"]
  --certDir, --cd           The absolute path to the directory for saving the created cert files. 
                            [string] [default: "/path/to/utils/node-ts/certs"]
```                                                         