# Python Utilities for Working with Modem Firmware v1.3+

[Modem firmware v1.3 and later](https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF9160-DK/Download#infotabs) provide new [AT security commands](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fref_at_commands%2FREF%2Fat_commands%2Fintro.html), including `KEYGEN` and `ATTESTTOKEN`, which are the focus of these Python scripts.

## Prerequisites

Use Python pip to install missing packages such as `cbor2`, `pyserial`, `colorama` and `pyOpenSSL`.

```
~$ pip3 install cbor2 pyserial colorama pyOpenSSL
```

## Create CA Cert
This script creates a self-signed CA certificate and an associated EC keypair.   The CA cert and private key can then be used to create device credentials.  Generally, this script needs to be called only once and then its output can be used to produce many device credentials.

The output file name format is as follows:
`<your_prefix><CA_serial_number_hex>_ca.pem`
`<your_prefix><CA_serial_number_hex>_prv.pem`
`<your_prefix><CA_serial_number_hex>_pub.pem`

```
usage: create_ca_cert.py [-h] -c,  C,  [-st ST] [-l L] [-o O] [-ou OU] [-cn CN] [-dv DV] [-e EMAIL] [-p PATH] [-f FILEPREFIX]

Create CA Certificate

optional arguments:
  -h, --help            show this help message and exit
  -c,  C,               2 character country code
  -st ST                State or Province
  -l L                  Locality
  -o O                  Organization
  -ou OU                Organizational Unit
  -cn CN                Common Name
  -dv DV                Number of days valid
  -e EMAIL, --email EMAIL
                        E-mail address
  -p PATH, --path PATH  Path to save PEM files.
  -f FILEPREFIX, --fileprefix FILEPREFIX
                        Prefix for output files
```
## Example
```
python3 create_ca_cert.py -c US -st OR -l Portland -o "My Company" -ou "RD" -cn example.com -e admin@example.com -p /my_ca -f my_company-
Creating self-signed CA certificate...
File created: /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_ca.pem
File created: /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_prv.pem
File created: /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_pub.pem
```

## Device Credentials Installer

This script automates the process of generating and programming device credentials to a device such as a Thingy:91 or 9160DK running an nRF Connect SDK application containing the AT host library.
It can also install on an LTE gateway, by interacting with the built-in shell.

It requires you to use the `create_ca_cert.py` above once ahead of time to generate the required CA and CA key.

It utilizes methods within the classes inside the other scripts `modem_credentials_parser.py` and `create_device_credentials.py`.
You do not need to use them directly unless `device_credentials_installer.py` does not meet your needs.

Note: if only a single supported device is detected on a serial port, it will be automatically selected and used.
Otherwise, the script displays a list of detected devices and gives the user a choice of which to use.

```
usage: device_credentials_installer.py [-h] [--dv DV] [--ca CA] [--ca_key CA_KEY] [--csv CSV] [--port PORT] [-a] [-A]
                                       [-g] [-f FILEPREFIX] [-v] [-s] [-S SECTAG] [-p PATH] [-P] [-d] [-w PASSWORD]
                                       [-t TAGS] [-T SUBTYPE] [-F FWTYPES]

Device Credentials Installer

optional arguments:
  -h, --help            show this help message and exit
  --dv DV               Number of days cert is valid (default: 3650)
  --ca CA               Filepath to your CA cert PEM (default: )
  --ca_key CA_KEY       Filepath to your CA's private key PEM (default: )
  --csv CSV             Filepath to provisioning csv file (default: provision.csv)
  --port PORT           Specify which serial port to open, otherwise pick from list (default: None)
  -a, --append          When saving provisioning csv, append to it (default: False)
  -A, --all             List ports of all types, not just Nordic devices (default: False)
  -g, --gateway         Force use of shell commands to enter and exit at command mode (default: False)
  -f FILEPREFIX, --fileprefix FILEPREFIX
                        Prefix for output files (<prefix><UUID>_<sec_tag>_<type>.pem). Selects -s (default: )
  -v, --verbose         bool: make output verbose (default: False)
  -s, --save            Save PEM file(s): <UUID>_<sec_tag>_<type>.pem (default: False)
  -S SECTAG, --sectag SECTAG
                        integer: security tag to use (default: 42)
  -p PATH, --path PATH  Path to save files. Selects -s (default: ./)
  -P, --plain           bool: plain output (no colors) (default: False)
  -d, --delete          bool: delete sectag from modem first (default: False)
  -w PASSWORD, --password PASSWORD
                        nRF Cloud Gateway password (default: nordic)
  -t TAGS, --tags TAGS  pipe (|) delimited device tags (default: )
  -T SUBTYPE, --subtype SUBTYPE
                        custom device type (default: )
  -F FWTYPES, --fwtypes FWTYPES
                        pipe (|) delimited firmware types for FOTA of the set {APP MODEM BOOT SOFTDEVICE BOOTLOADER}
                        (default: APP|MODEM)
```

## Examples

### Thingy:91 under Linux

```
~/src/utils$ python3 device_credentials_installer.py -A -d --port /dev/ttyS38 --ca CA0x522400c80ef6d95ea65ef4860d12adc1b031aa9_ca.pem --ca_key CA0x522400c80ef6d95ea65ef4860d12adc1b031aa9_prv.pem --csv provision.csv

opening port /dev/ttyS38 as generic device...
disabling LTE and GNSS...
-> AT+CFUN=4
<- OK
deleting sectag 42...
-> AT%CMNG=3,42,0
<- OK
-> AT%CMNG=3,42,1
<- OK
-> AT%CMNG=3,42,2
<- OK
requesting CSR for sectag 42...
-> AT%KEYGEN=42,2,0
<- %KEYGEN: "MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMyLTQ4MzQtODAyYi0wOTA4NzE4MzE0ZGMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATPLBN5-YWj13l6NWeqNFW8VjHOWZB5IfeaEyfMeiUk6V1NEMuYnEBwwrBdV94F5XdscCKDLtvtyKo4VTbnK-mPoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiAO2KmzF9Ms599GC3EueXhmp6AWwtD6c7bA_lhnNc7ZgQIhAMFJC99z_GfLJxCT2U8Dt4MFCB_5wwFYSDcSg-ucfLHS.0oRDoQEmoQRBIVhM2dn3hQlQUDYxVDkySDSAKwkIcYMU3EIYKlgglFk5S_wQVOvIPvm-qjnYS4BZ4mCg7Bsf3cAVIGelPGNQVF8u_v_HrhBJH107c3QBLVhA35AZa4ZWQbm7mRQfFuGGlfLFgiNwMLxxjsmiQHNtT01o5c6pm2uEqMn0T_YY0aEXZer2hCS-YwNoW97zcH_Iug"
<- OK

Parsing AT%KEYGEN output:

-----BEGIN CERTIFICATE REQUEST-----
MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMyLTQ4MzQtODAyYi0w
OTA4NzE4MzE0ZGMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATPLBN5+YWj13l6
NWeqNFW8VjHOWZB5IfeaEyfMeiUk6V1NEMuYnEBwwrBdV94F5XdscCKDLtvtyKo4
VTbnK+mPoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwDAYIKoZIzj0E
AwIFAANIADBFAiAO2KmzF9Ms599GC3EueXhmp6AWwtD6c7bA/lhnNc7ZgQIhAMFJ
C99z/GfLJxCT2U8Dt4MFCB/5wwFYSDcSg+ucfLHS
-----END CERTIFICATE REQUEST-----

Device public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzywTefmFo9d5ejVnqjRVvFYxzlmQ
eSH3mhMnzHolJOldTRDLmJxAcMKwXVfeBeV3bHAigy7b7ciqOFU25yvpjw==
-----END PUBLIC KEY-----

SHA256 Digest:
9459394bfc1054ebc83ef9beaa39d84b8059e260a0ec1b1fddc0152067a53c63

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Payload ID: CSR_msg_v1
    Dev UUID:   50363154-3932-4834-802b-0908718314dc
    sec_tag:    42
    SHA256:     9459394bfc1054ebc83ef9beaa39d84b8059e260a0ec1b1fddc0152067a53c63
    Nonce:      545f2efeffc7ae10491f5d3b7374012d
  ---------------
  Sig:
      df90196b865641b9bb99141f16e18695f2c582237030bc718ec9a240736d4f4d68e5cea99b6b84a8c9f44ff618d1a11765eaf68424be6303685bdef3707fc8ba

COSE digest matches payload
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
Device ID (UUID): 50363154-3932-4834-802b-0908718314dc
loading ca and key...
Creating device certificate...
writing AWS CA to modem...
-> AT%CMNG=0,42,0,"-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----
"
<- OK
writing dev cert to modem...
-> AT%CMNG=0,42,1,"-----BEGIN CERTIFICATE-----
MIIBxzCCAW4CFDgXQgyjalFBw6ypq3BGKS/jQw4gMAoGCCqGSM49BAMCMIGdMQsw
CQYDVQQGEwJVUzELMAkGA1UECAwCT1IxETAPBgNVBAcMCFBvcnRsYW5kMR0wGwYD
VQQKDBROb3JkaWMgU2VtaWNvbmR1Y3RvcjELMAkGA1UECwwCUkQxFzAVBgNVBAMM
Dm5vcmRpY3NlbWkuY29tMSkwJwYJKoZIhvcNAQkBFhpwZXRlci5za2VnZ3NAbm9y
ZGljc2VtaS5ubzAeFw0yMTA4MjQwMDE2MjBaFw0zMTA4MjIwMDE2MjBaMC8xLTAr
BgNVBAMMJDUwMzYzMTU0LTM5MzItNDgzNC04MDJiLTA5MDg3MTgzMTRkYzBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABM8sE3n5haPXeXo1Z6o0VbxWMc5ZkHkh95oT
J8x6JSTpXU0Qy5icQHDCsF1X3gXld2xwIoMu2+3IqjhVNucr6Y8wCgYIKoZIzj0E
AwIDRwAwRAIgLwud64ojEI99F18wHLxzwVNe84OjcoL+NpnOKGqzZ20CIEQhqq3d
ViL+OKPpdSX0ldid9iywwHSYOdQCwmbv86Lk
-----END CERTIFICATE-----
"
<- OK
saving provisioning endpoint csv file provision.csv...
--- file provision.csv exists; overwrite, append, or quit (y,a,n)? y
file saved

~/src/utils$
```

### 9160DK under Windows

```
C:\utils>python device_credentials_installer.py -d --ca CA0x522400c80ef6d95ea65ef4860d12adc1b031aa9_ca.pem --ca_key CA0x522400c80ef6d95ea65ef4860d12adc1b031aa9_prv.pem --csv provision.csv

Available ports:
 1: COM48                nRF9160-DK
opening port COM48 as generic device...
disabling LTE and GNSS...
-> AT+CFUN=4
<- +CSCON: 1
<- [00:00:28.460,540] <inf> asset_tracker: RRC mode: Connected
<- +CEREG: 0
<- [00:00:28.467,834] <inf> asset_tracker: LTE cell changed: Cell ID: -1, Tracking area: -1
<- +CSCON: 0
<- [00:00:29.778,564] <inf> asset_tracker: RRC mode: Idle
<- OK
deleting sectag 42...
-> AT%CMNG=3,42,0
<- OK
-> AT%CMNG=3,42,1
<- OK
-> AT%CMNG=3,42,2
<- OK
requesting CSR for sectag 42...
-> AT%KEYGEN=42,2,0
<- %KEYGEN: "MIIBCTCBrwIBADAvMS0wKwYDVQQDDCQ1MDUwMzY0Mi0zMjM5LTRmYWEtODBkYi0wZjI4ZTM1NmFkOTUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARp8RD-O71kVsE5jKDox86WMSrDAdJOR1QhGybEvRDLTOcxk71eOfWbEHXxAIXa3ZHXUFEuFz76LoivjZUdWN2KoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANHADBEAiBK1YEDqdwvdWW4y_suz3wlLv11GorZYITgqYPQZL9MmwIgMcFAgyW7hDPFoboweWlVGPys0Vi8nwGg5MaRiaqKxaE.0oRDoQEmoQRBIVhM2dn3hQlQUFA2QjI5T6qA2w8o41atlUIYKlgglD8Gwbrr2nOl8YjYqDVJ4ZqBjNo1bHO4QkdWGibvIXRQUH5ITh55jR_gjPejMo6PpVhA6Ig3EJLFwDUrXzdjRITFvIFlR1NtczbzIu8DtO6sYyWPW7HeYeaMv7EUvvOEykgA338zCKlwtzgmBT6SS1-7sQ"
<- OK

Parsing AT%KEYGEN output:

-----BEGIN CERTIFICATE REQUEST-----
MIIBCTCBrwIBADAvMS0wKwYDVQQDDCQ1MDUwMzY0Mi0zMjM5LTRmYWEtODBkYi0w
ZjI4ZTM1NmFkOTUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARp8RD+O71kVsE5
jKDox86WMSrDAdJOR1QhGybEvRDLTOcxk71eOfWbEHXxAIXa3ZHXUFEuFz76Loiv
jZUdWN2KoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwDAYIKoZIzj0E
AwIFAANHADBEAiBK1YEDqdwvdWW4y/suz3wlLv11GorZYITgqYPQZL9MmwIgMcFA
gyW7hDPFoboweWlVGPys0Vi8nwGg5MaRiaqKxaE=
-----END CERTIFICATE REQUEST-----

Device public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEafEQ/ju9ZFbBOYyg6MfOljEqwwHS
TkdUIRsmxL0Qy0znMZO9Xjn1mxB18QCF2t2R11BRLhc++i6Ir42VHVjdig==
-----END PUBLIC KEY-----

SHA256 Digest:
943f06c1baebda73a5f188d8a83549e19a818cda356c73b84247561a26ef2174

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Payload ID: CSR_msg_v1
    Dev UUID:   50503642-3239-4faa-80db-0f28e356ad95
    sec_tag:    42
    SHA256:     943f06c1baebda73a5f188d8a83549e19a818cda356c73b84247561a26ef2174
    Nonce:      507e484e1e798d1fe08cf7a3328e8fa5
  ---------------
  Sig:
      e888371092c5c0352b5f37634484c5bc816547536d7336f322ef03b4eeac63258f5bb1de61e68cbfb114bef384ca4800df7f3308a970b73826053e924b5fbbb1

COSE digest matches payload
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
Device ID (UUID): 50503642-3239-4faa-80db-0f28e356ad95
loading ca and key...
Creating device certificate...
writing AWS CA to modem...
-> AT%CMNG=0,42,0,"-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----
"
<- OK
writing dev cert to modem...
-> AT%CMNG=0,42,1,"-----BEGIN CERTIFICATE-----
MIIByDCCAW4CFB/Z7a9srkCl7H5KYiFGAxgT+/hmMAoGCCqGSM49BAMCMIGdMQsw
CQYDVQQGEwJVUzELMAkGA1UECAwCT1IxETAPBgNVBAcMCFBvcnRsYW5kMR0wGwYD
VQQKDBROb3JkaWMgU2VtaWNvbmR1Y3RvcjELMAkGA1UECwwCUkQxFzAVBgNVBAMM
Dm5vcmRpY3NlbWkuY29tMSkwJwYJKoZIhvcNAQkBFhpwZXRlci5za2VnZ3NAbm9y
ZGljc2VtaS5ubzAeFw0yMTA4MjQwMDIwMjVaFw0zMTA4MjIwMDIwMjVaMC8xLTAr
BgNVBAMMJDUwNTAzNjQyLTMyMzktNGZhYS04MGRiLTBmMjhlMzU2YWQ5NTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABGnxEP47vWRWwTmMoOjHzpYxKsMB0k5HVCEb
JsS9EMtM5zGTvV459ZsQdfEAhdrdkddQUS4XPvouiK+NlR1Y3YowCgYIKoZIzj0E
AwIDSAAwRQIgSVFtTVQiXqcJ2OeNVj2sz9s+P0pW546Dp+f+wKDKuQQCIQC1tzn9
F5cAnMPJquIpWKusP/S/3U4QgvKjq6GYndk6nA==
-----END CERTIFICATE-----
"
<- OK
saving provisioning endpoint csv file provision.csv...
file saved

C:\utils>
```

## Modem Credentials Parser
The script above, `device_credentials_installer.py` makes use of this script, `modem_credentials_parser.py`, so if you use the former, you do not need to also follow the directions below.  If `device_credentials_installer.py` does not meet your needs, you can use `modem_credentials_parser.py` directly to take advantage of additional options.

This script parses the output of `AT%KEYGEN` and `AT%ATTESTTOKEN`.   Each command outputs two base64 strings joined by a `.` character.  The first string is the command specific data.  The second string is the [COSE](https://datatracker.ietf.org/doc/html/rfc8152) signature of the first string.
The parsed data is displayed in the output.  Providing the COSE string to this script is optional, as it is only used to display extra information.  When providing `AT%KEYGEN` output, PEM files can be optionally saved.


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

Parse modem [KEYGEN](https://infocenter.nordicsemi.com/topic/ref_at_commands/REF/at_commands/security/keygen_set.html) output; with or without COSE string:

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output>`

Parse modem keygen output and save PEM file(s); COSE string is required:

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output> -s`

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output> -p <my_output_path> -f <my_file_prefix>`

Parse modem [ATTESTTOKEN](https://infocenter.nordicsemi.com/topic/ref_at_commands/REF/at_commands/security/attesttoken_set.html) output; with or without COSE string:

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

## Create Device Credentials
The script above, `device_credentials_installer.py` makes use of this script, `create_device_credentials.py`, so if you use the former, you do not need to also follow the directions below.  If `device_credentials_installer.py` does not meet your needs, you can use `create_device_credentialsr.py` directly to take advantage of additional options.

This script creates device credentials for use with nRF Cloud.  It requires a CA certificate and the associated private key as an input.  It optionally accepts a CSR (from `AT%KEYGEN`/modem_credentials_parser.py).

The output file name format is as follows:
`<your_prefix><CN>_crt.pem`
`<your_prefix><CN>_pub.pem`
if no CSR provided:
`<your_prefix><CN>_prv.pem`
If no CN (common name) is provided/available, the serial number hex value will be used.
```
usage: create_device_credentials.py [-h] -ca CA -ca_key CA_KEY -c C [-st ST] [-l L] [-o O] [-ou OU] [-cn CN] [-e EMAIL] [-dv DV]
            [-p PATH] [-f FILEPREFIX] [-csr CSR]

Create Device Credentials

optional arguments:
  -h, --help            show this help message and exit
  -ca CA                Filepath to your CA cert PEM
  -ca_key CA_KEY        Filepath to your CA's private key PEM
  -c C                  2 character country code; required if CSR is not provided
  -st ST                State or Province; ignored if CSR is provided
  -l L                  Locality; ignored if CSR is provided
  -o O                  Organization; ignored if CSR is provided
  -ou OU                Organizational Unit; ignored if CSR is provided
  -cn CN                Common Name; use nRF Cloud device ID/MQTT client ID; ignored if CSR is provided
  -e EMAIL, --email EMAIL
                        E-mail address; ignored if CSR is provided
  -dv DV                Number of days cert is valid
  -p PATH, --path PATH  Path to save PEM files.
  -f FILEPREFIX, --fileprefix FILEPREFIX
                        Prefix for output files
  -csr CSR              Filepath to CSR PEM from device
```

## Examples

### No CSR provided:
```
python3 create_device_credentials.py -ca /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_ca.pem -ca_key /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_prv.pem -c US -st WA -l Seattle -o "My Company" -ou "Devs" -cn my-unique-device-id -e email@example.com -dv 2000 -p /dev_credentials -f hw_rev2-
Creating device credentials...
File created: /dev_credentials/hw_rev2-my-unique-device-id_crt.pem
File created: /dev_credentials/hw_rev2-my-unique-device-id_pub.pem
File created: /dev_credentials/hw_rev2-my-unique-device-id_prv.pem
```

### CSR provided:
```
python3 create_device_credentials.py -ca /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_ca.pem -ca_key /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_prv.pem -csr /my_devices/pem_files/hw_rev2-50363154-3931-44f0-8022-121b6401627d_17_csr.pem -dv 2000 -p /dev_credentials -f hw_rev2-
Creating device credentials...
File created: /dev_credentials/hw_rev2-50363154-3931-44f0-8022-121b6401627d_crt.pem
File created: /dev_credentials/hw_rev2-50363154-3931-44f0-8022-121b6401627d_pub.pem
```
