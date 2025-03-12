"""
Test for modem_credentials_parser.py
"""


import pytest

from unittest.mock import Mock
from nrfcloud_utils import modem_credentials_parser

KEYGEN_CSR = "MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EXnw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qWMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQlQUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZuXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8UXfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud"
KEYGEN_CSR_DATA = {
    "CSR_PEM": b'-----BEGIN CERTIFICATE REQUEST-----\nMIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0x\nMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o/EX\nnw62bnQWr8+JqsNh/HZxS3k3bMD4KZ8+qxnvgeoiqQ5zAycEP/Wcmzqypvwyf3qW\nMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwDAYIKoZIzj0E\nAwIFAANIADBFAiEAv7OLZ/dXbszfhhjcLMUT72wTmw+z6GlgWxVhyWgR27ACIAvY\n/lPu3yfYZY5AL6uYTkUFp4GQkbSOUC/lsHyCxOuG\n-----END CERTIFICATE REQUEST-----\n',
    "PUB_PEM" : b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKg+qTX2tvaPxF58Otm50Fq/PiarD\nYfx2cUt5N2zA+CmfPqsZ74HqIqkOcwMnBD/1nJs6sqb8Mn96ljK2dlQeWg==\n-----END PUBLIC KEY-----\n',
    "UUID" : "50363154-3931-44f0-8022-121b6401627d",
    "SEC_TAG" : "17",
}

ATTESTTOKEN = "2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY"
ATTESTTOKEN_DATA = {
    "UUID" : "50363154-3931-44f0-8022-121b6401627d",
}

class TestATClient:
    def test_parse_keygen_output_csr(self):
        csr_pem_bytes, pub_key_bytes, dev_uuid_hex_str, sec_tag_str = \
            modem_credentials_parser.parse_keygen_output(KEYGEN_CSR)
        assert csr_pem_bytes == KEYGEN_CSR_DATA["CSR_PEM"]
        assert pub_key_bytes == KEYGEN_CSR_DATA["PUB_PEM"]
        assert dev_uuid_hex_str == KEYGEN_CSR_DATA["UUID"]
        assert sec_tag_str == KEYGEN_CSR_DATA["SEC_TAG"]

    def test_attesttoken(self):
        _, _ = modem_credentials_parser.parse_attesttoken_output(ATTESTTOKEN)
        uuid = modem_credentials_parser.get_device_uuid(ATTESTTOKEN)
        assert uuid == ATTESTTOKEN_DATA["UUID"]

    def test_command(self):
        modem_credentials_parser.main(["-k", KEYGEN_CSR])
        modem_credentials_parser.main(["-a", ATTESTTOKEN])
