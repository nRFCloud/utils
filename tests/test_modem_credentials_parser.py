"""
Test for modem_credentials_parser.py
"""



from nrfcloud_utils import modem_credentials_parser

KEYGEN_CSR = "MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EXnw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qWMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQlQUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZuXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8UXfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud"
KEYGEN_CSR_DATA = {
    "CSR_PEM": b'-----BEGIN CERTIFICATE REQUEST-----\nMIIBCDCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0x\nMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o/EX\nnw62bnQWr8+JqsNh/HZxS3k3bMD4KZ8+qxnvgeoiqQ5zAycEP/Wcmzqypvwyf3qW\nMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwCgYIKoZIzj0E\nAwIDSAAwRQIhAL+zi2f3V27M34YY3CzFE+9sE5sPs+hpYFsVYcloEduwAiAL2P5T\n7t8n2GWOQC+rmE5FBaeBkJG0jlAv5bB8gsTrhg==\n-----END CERTIFICATE REQUEST-----\n',
    "CSR_PEM_NORMALIZED": b'-----BEGIN CERTIFICATE REQUEST-----\nMIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0x\nMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o/EX\nnw62bnQWr8+JqsNh/HZxS3k3bMD4KZ8+qxnvgeoiqQ5zAycEP/Wcmzqypvwyf3qW\nMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwDAYIKoZIzj0E\nAwIFAANIADBFAiEAv7OLZ/dXbszfhhjcLMUT72wTmw+z6GlgWxVhyWgR27ACIAvY\n/lPu3yfYZY5AL6uYTkUFp4GQkbSOUC/lsHyCxOuG\n-----END CERTIFICATE REQUEST-----\n',
    "PUB_PEM" : b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKg+qTX2tvaPxF58Otm50Fq/PiarD\nYfx2cUt5N2zA+CmfPqsZ74HqIqkOcwMnBD/1nJs6sqb8Mn96ljK2dlQeWg==\n-----END PUBLIC KEY-----\n',
    "UUID" : "50363154-3931-44f0-8022-121b6401627d",
    "SEC_TAG" : "17",
}

KEYGEN_CSR_NORMALIZED = "MIIBBzCBrwIBADAvMS0wKwYDVQQDDCQ1MDM0Mzk1Ni0zMDM3LTQ3MzgtODAwZC0xZjI5ZTBhMGY3YmYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0N0OGqO91QKMOJdJpSsAQbotqXNto_B-3rAggRKfvLNjQxhwnNoBAZ-b8ecoNLAR3kZnx5G5K3PjNCSj3KD8hoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwCgYIKoZIzj0EAwIDRwAwRAIgV0WWIwPLZCMXsl8a-Umc7yTL3V4FuA3a9IEB0I1zjLECIHkrki8nS8X27nfYSLnbz_5lBvOZQjMn1ttZChLW31WO.0oRDoQEmoQRBIVhN2dn3hQlQUDQ5VjA3RziADR8p4KD3v0MZBNNYIGn-n_c55m-bB8f3kplNZ51kSw1bFY6PN31dlRwicMIEUCcaM3CUJG_LHnzHUntrtTJYQFttq5NPZ1TWYvpAUNyulC71-ZJdtCdgaT3ejcV_GGFuD-7Z2A163d1uVjddQ7VukItM2jFWi2i5C4gnNAPmzeM"
KEYGEN_CSR_NORMALIZED_DATA = {
    "CSR_PEM": b'-----BEGIN CERTIFICATE REQUEST-----\nMIIBBzCBrwIBADAvMS0wKwYDVQQDDCQ1MDM0Mzk1Ni0zMDM3LTQ3MzgtODAwZC0x\nZjI5ZTBhMGY3YmYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0N0OGqO91QKMO\nJdJpSsAQbotqXNto/B+3rAggRKfvLNjQxhwnNoBAZ+b8ecoNLAR3kZnx5G5K3PjN\nCSj3KD8hoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwCgYIKoZIzj0E\nAwIDRwAwRAIgV0WWIwPLZCMXsl8a+Umc7yTL3V4FuA3a9IEB0I1zjLECIHkrki8n\nS8X27nfYSLnbz/5lBvOZQjMn1ttZChLW31WO\n-----END CERTIFICATE REQUEST-----\n',
    "PUB_PEM" : b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdDdDhqjvdUCjDiXSaUrAEG6Lalzb\naPwft6wIIESn7yzY0MYcJzaAQGfm/HnKDSwEd5GZ8eRuStz4zQko9yg/IQ==\n-----END PUBLIC KEY-----\n',
    "UUID" : "50343956-3037-4738-800d-1f29e0a0f7bf",
    "SEC_TAG" : "1235",
}


ATTESTTOKEN = "2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY"
ATTESTTOKEN_DATA = {
    "UUID" : "50363154-3931-44f0-8022-121b6401627d",
}

class TestModemCredentialsParser:
    def test_parse_keygen_output_csr(self):
        csr_pem_bytes, pub_key_bytes, dev_uuid_hex_str, sec_tag_str = \
            modem_credentials_parser.parse_keygen_output(KEYGEN_CSR)
        assert csr_pem_bytes == KEYGEN_CSR_DATA["CSR_PEM"] or KEYGEN_CSR_DATA["CSR_PEM_NORMALIZED"]
        assert pub_key_bytes == KEYGEN_CSR_DATA["PUB_PEM"]
        assert dev_uuid_hex_str == KEYGEN_CSR_DATA["UUID"]
        assert sec_tag_str == KEYGEN_CSR_DATA["SEC_TAG"]

    def test_parse_keygen_output_csr_normalized(self):
        csr_pem_bytes, pub_key_bytes, dev_uuid_hex_str, sec_tag_str = \
            modem_credentials_parser.parse_keygen_output(KEYGEN_CSR_NORMALIZED)
        assert csr_pem_bytes == KEYGEN_CSR_NORMALIZED_DATA["CSR_PEM"]
        assert pub_key_bytes == KEYGEN_CSR_NORMALIZED_DATA["PUB_PEM"]
        assert dev_uuid_hex_str == KEYGEN_CSR_NORMALIZED_DATA["UUID"]
        assert sec_tag_str == KEYGEN_CSR_NORMALIZED_DATA["SEC_TAG"]

    def test_attesttoken(self):
        _, _ = modem_credentials_parser.parse_attesttoken_output(ATTESTTOKEN)
        uuid = modem_credentials_parser.get_device_uuid(ATTESTTOKEN)
        assert uuid == ATTESTTOKEN_DATA["UUID"]

    def test_command(self):
        modem_credentials_parser.main(["-k", KEYGEN_CSR])
        modem_credentials_parser.main(["-a", ATTESTTOKEN])
