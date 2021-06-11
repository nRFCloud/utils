# NodeJS (Typescript) Utilities for Working with nRF Cloud

The main use of these scripts is with the [ProvisionDevices endpoint](https://api.nrfcloud.com/v1#operation/ProvisionDevices), which allows you to upload a CSV file containing one or more deviceIds and ES256 certificates in PEM format, created with your own CA certificate. These scripts demonstrate how you can programmatically generate a CA cert and corresponding device certificates that will work on nRF Cloud.

See the top of each file for example usage.

## CA Certificate Creator
```
--cnSubjectPrefix           The prefix for the cert Subject. [string] [required]
--ouName, --ou              The Organizational Unit (OU) name of the cert Subject. [string] [required]
--certFileNamePrefix, --fn  The prefix for the CA cert files. [string] [default: "ca-cert"]
--certDir, --cd             The absolute path to the directory to save the created cert files. 
                            [string] [default: "/path/to/utils/node-ts/certs"]
--help                      Show help [boolean]                            
```

## Device Certificate Creator
```
--deviceId                  [string] [default: "e7570b93-65cd-45ce-8c01-813fc3feb96e"]
--cnSubject                 [string] [required] [default: "/C=NO/ST=Trondelag/L=Trondheim/O=Nordic Semiconductor ASA"]
--certDir, --cd             The absolute path to the directory for storing the
                            created CSR and certificate files. [string] [default: "/path/to/utils/node-ts/certs"]
--csrFileName, --csr        Name of your CSR pem file. [string]
--caCertKeyFileName, --cak  Name of your CA private key pem file [string] [required] [default: "ca-cert.key.pem"]
--caCertPemFileName, --cac  Name of your CA certificate pem file [string] [required] [default: "ca-cert.crt.pem"]
--help                      Show help [boolean]
```                                                         