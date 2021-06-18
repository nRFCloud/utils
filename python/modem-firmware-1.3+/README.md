# Python Utilities for Working with Modem Firmware v1.3+

[Modem firmware v1.3 and later](https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF9160-DK/Download#infotabs) provide new [AT security commands](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fref_at_commands%2FREF%2Fat_commands%2Fintro.html), including `KEYGEN` and `ATTESTTOKEN`, which are the focus of these Python scripts.

## Modem Credential Parser Example

```
usage: modem_credentials_parser.py [-h] [-k KEYGEN] [-a ATTEST]

Modem Credentials Parser

optional arguments:
  -h, --help                  show this help message and exit
  -k KEYGEN, --keygen KEYGEN
                              base64url string: KEYGEN output
  -a ATTEST, --attest ATTEST
                              base64url string: ATTESTTOKEN output
  -s, --save                  Save PEM file(s): <UUID>_<sec_tag>_<type>.pem
  -p PATH, --path PATH        Path to save PEM file. Selects -s
  -f FILEPREFIX, --fileprefix FILEPREFIX
                              Prefix for output files (<prefix><UUID>_<sec_tag>_<type>.pem). Selects -s
```

Parse modem [KEYGEN](https://infocenter.nordicsemi.com/topic/ref_at_commands/REF/at_commands/security/keygen_set.html) output; with or without COSE portion:

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output>`

Parse modem keygen output and save PEM file(s); COSE portion is required:

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output> -s`

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output> -p <my_output_path> -f <my_file_prefix>`

Parse modem [ATTESTTOKEN](https://infocenter.nordicsemi.com/topic/ref_at_commands/REF/at_commands/security/attesttoken_set.html) output; with or without COSE portion:

`python3 modem_credentials_parser.py -a <base64url AT%ATTESTTOKEN output>`

## Examples

### KEYGEN - Certificate Signing Request (CSR): `AT%KEYGEN=17,2,0`
```
python3 modem_credentials_parser.py -k MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EXnw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qWMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQlQUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZuXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8UXfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud

Parsing AT%KEYGEN output:

-----BEGIN CERTIFICATE REQUEST-----
MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0x
MjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o/EX
nw62bnQWr8+JqsNh/HZxS3k3bMD4KZ8+qxnvgeoiqQ5zAycEP/Wcmzqypvwyf3qW
MrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwDAYIKoZIzj0E
AwIFAANIADBFAiEAv7OLZ/dXbszfhhjcLMUT72wTmw+z6GlgWxVhyWgR27ACIAvY
/lPu3yfYZY5AL6uYTkUFp4GQkbSOUC/lsHyCxOuG
-----END CERTIFICATE REQUEST-----

Device public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKg+qTX2tvaPxF58Otm50Fq/PiarD
Yfx2cUt5N2zA+CmfPqsZ74HqIqkOcwMnBD/1nJs6sqb8Mn96ljK2dlQeWg==
-----END PUBLIC KEY-----

SHA256 Digest:
702a3d56f05b2f72531d650825e20041e2e9d9318c34b6853ab9066e5c72e80c

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Payload ID: CSR_msg_v1
    Dev UUID:  50363154-3931-44f0-8022-121b6401627d
    sec_tag:    17
    SHA256:     702a3d56f05b2f72531d650825e20041e2e9d9318c34b6853ab9066e5c72e80c
    Nonce:      1b8722ee1deb581566e2cb1359b27cd2
  ---------------
  Sig:
      d489397bc3016dd2112c0a2110b318fe842b69064f196bc5177dd032729c767da08e3c922b91f9a2492f3e63aff6b5302800c3750625a24ce8a6635c1913751d

COSE digest matches payload
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
```

### KEYGEN - Public Key: `AT%KEYGEN=16,2,1`
```
python3 modem_credentials_parser.py -k MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZKgDx0O0FKa7i1yFoxYngNdV5Csyi4rEPHcFTfeBVtkkJX-G0QZs-yesfzIaPs91b4x5xYN_g28k63gkeVMJwA.0oRDoQEmoQRBIVhL2dn3hQhQUDYxVDkxRPCAIhIbZAFifUEQWCDlovwqMVoJ1W-x93Tqypy2v_1ALv3-GCF1R9gYIy2WVlBQXvxKqA9JTveFh3nVwce-WEAMltwSSkVh8jSBPhP79ndSG0HJTOaTF9SExIq-FstjdLUW2inxdvVfqzLa05rgXqxshN5vfQIs22QT-swCt30h

Parsing AT%KEYGEN output:

Device public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZKgDx0O0FKa7i1yFoxYngNdV5Csy
i4rEPHcFTfeBVtkkJX+G0QZs+yesfzIaPs91b4x5xYN/g28k63gkeVMJwA==
-----END PUBLIC KEY-----

SHA256 Digest:
e5a2fc2a315a09d56fb1f774eaca9cb6bffd402efdfe18217547d818232d9656

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Payload ID: pubkey_msg_v2
    Dev UUID:   50363154-3931-44f0-8022-121b6401627d
    sec_tag:    16
    SHA256:     e5a2fc2a315a09d56fb1f774eaca9cb6bffd402efdfe18217547d818232d9656
    Nonce:      505efc4aa80f494ef7858779d5c1c7be
  ---------------
  Sig:
      0c96dc124a4561f234813e13fbf677521b41c94ce69317d484c48abe16cb6374b516da29f176f55fab32dad39ae05eac6c84de6f7d022cdb6413facc02b77d21

COSE digest matches payload
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
```

### AT%ATTESTTOKEN
```
python3 modem_credentials_parser.py -a 2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY

Parsing AT%ATTESTTOKEN output:

---------------
Msg Type:    Device identity message v1
Dev UUID:    50363154-3931-44f0-8022-121b6401627d
Dev Type:    NRF9160 SIAA
FW UUID:     1aff3acb-f1a6-4764-a263-4c2646c1c654
---------------
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Not present
  ---------------
  Sig:
      6b97c099628a71dceb10cfaee8b28ec697c9765b655a54b8e8471bd612f0bd3956e82509c26130de045215951a968780d9c71e7a3a6a18be779b4e79998070d6
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
```

### KEYGEN - Certificate Signing Request (CSR) + File Save: `AT%KEYGEN=17,2,0`
```
python3 modem_credentials_parser.py -k MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EXnw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qWMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQlQUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZuXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8UXfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud -p /my_devices/pem_files -f hw_rev2-

Parsing AT%KEYGEN output:

-----BEGIN CERTIFICATE REQUEST-----
MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0x
MjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o/EX
nw62bnQWr8+JqsNh/HZxS3k3bMD4KZ8+qxnvgeoiqQ5zAycEP/Wcmzqypvwyf3qW
MrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwDAYIKoZIzj0E
AwIFAANIADBFAiEAv7OLZ/dXbszfhhjcLMUT72wTmw+z6GlgWxVhyWgR27ACIAvY
/lPu3yfYZY5AL6uYTkUFp4GQkbSOUC/lsHyCxOuG
-----END CERTIFICATE REQUEST-----

Device public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKg+qTX2tvaPxF58Otm50Fq/PiarD
Yfx2cUt5N2zA+CmfPqsZ74HqIqkOcwMnBD/1nJs6sqb8Mn96ljK2dlQeWg==
-----END PUBLIC KEY-----

SHA256 Digest:
702a3d56f05b2f72531d650825e20041e2e9d9318c34b6853ab9066e5c72e80c

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Payload ID: CSR_msg_v1
    Dev UUID:   50363154-3931-44f0-8022-121b6401627d
    sec_tag:    17
    SHA256:     702a3d56f05b2f72531d650825e20041e2e9d9318c34b6853ab9066e5c72e80c
    Nonce:      1b8722ee1deb581566e2cb1359b27cd2
  ---------------
  Sig:
      d489397bc3016dd2112c0a2110b318fe842b69064f196bc5177dd032729c767da08e3c922b91f9a2492f3e63aff6b5302800c3750625a24ce8a6635c1913751d

COSE digest matches payload
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
Argument -s has been selected since path/fileprefix was specified
File created: /my_devices/pem_files/hw_rev2-50363154-3931-44f0-8022-121b6401627d_17_csr.pem
File created: /my_devices/pem_files/hw_rev2-50363154-3931-44f0-8022-121b6401627d_17_pub.pem
```
