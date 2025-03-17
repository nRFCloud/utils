#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

from enum import Enum
from abc import ABC, abstractmethod
from nrfcloud_utils.cli_helpers import local_style, error_style
import math
import time
from nrfcloud_utils import modem_credentials_parser
import base64
import hashlib
from cryptography import x509

IMEI_LEN = 15

class CredentialCommandInterface(ABC):
    def __init__(self, serial_write_line, serial_wait_for_response, verbose):
        """Initialize a Credentials Command Interface

        Args:
            write_line: A function which the interface will use to write commands to the serial
                        interface. Should accept a single string, and write that string as a single
                        line to the serial interface.
            serial_wait_for_prompt: A function which can be called to wait for responses or prompts
                                    from the serial interface.
            verbose: Whether or not to operate in verbose mode.
        """
        self.serial_write_line = serial_write_line
        self.serial_wait_for_response = serial_wait_for_response
        self.verbose = verbose

    def write_raw(self, command):
        """Write a raw line directly to the serial interface."""
        self.serial_write_line(command)

    @abstractmethod
    def write_credential(self, sectag, cred_type, cred_text):
        """Write a credential string to the command interface"""
        return

    @abstractmethod
    def delete_credential(self, sectag, cred_type):
        """Delete a credential using command interface"""
        return

    @abstractmethod
    def check_credential_exists(self, sectag, cred_type, get_hash=True):
        """Verify that a credential is installed. If check_hash is true, retrieve the SHA hash."""
        return

    @abstractmethod
    def calculate_expected_hash(self, cred_text):
        """Returns the expected digest/hash for a given credential as a string"""
        return

    @abstractmethod
    def get_csr(self, sectag = 0, cn = ""):
        """Generate a private/public keypair and a corresponding Certificate Signing Request.

        Returns:
            CSR as X509Req object.
        """
        return

    @abstractmethod
    def go_offline(self):
        """Tell the device to go offline so that credentials can be modified"""
        return

    @abstractmethod
    def get_imei(self):
        """Get device IMEI, if applicable"""
        return

    @abstractmethod
    def get_mfw_version(self):
        """Get modem firmware version, if applicable"""
        return

class ATKeygenException(Exception):
    def __init__(self, message, exit_code):
        super().__init__(message)
        self.exit_code = exit_code

class ATCommandInterface(CredentialCommandInterface):
    shell = False

    def _parse_sha(self, cmng_result_str):
        # Example AT%CMNG response:
        #   %CMNG: 123,0,"2C43952EE9E000FF2ACC4E2ED0897C0A72AD5FA72C3D934E81741CBD54F05BD1"
        # The first item in " is the SHA.
        try:
            return cmng_result_str.decode().split('"')[1]
        except (ValueError, IndexError):
            print(error_style(f'Could not parse credential hash: {cmng_result_str}'))
            return None

    def set_shell_mode(self, shell):
        self.shell = shell

    def at_command(self, at_command, wait_for_result=False):
        """Write an AT command to the command interface. Optionally wait for OK"""

        # AT commands are written directly as-is with the ATCommandInterface:
        at_cmd_prefix = 'at ' if self.shell else ''
        self.write_raw(f'{at_cmd_prefix}{at_command}')

        if wait_for_result:
            result, output = self.serial_wait_for_response(b'OK', b'ERROR')
            return result
        else:
            return True

    def write_credential(self, sectag, cred_type, cred_text):
        result = self.at_command(f'AT%CMNG=0,{sectag},{cred_type},"{cred_text}"',
                                 wait_for_result=True)
        time.sleep(1)
        return result

    def delete_credential(self, sectag, cred_type):
        # No output is expected beyond OK/ERROR in this case
        return self.at_command(f'AT%CMNG=3,{sectag},{cred_type}', wait_for_result=True)

    def check_credential_exists(self, sectag, cred_type, get_hash=True):
        self.at_command(f'AT%CMNG=1,{sectag},{cred_type}')
        retval, res = self.serial_wait_for_response(b'OK', b'ERROR', store=b'%CMNG')
        if retval and res:
            if not get_hash:
                return True, None
            else:
                return True, self._parse_sha(res)

        return False, None

    def calculate_expected_hash(self, cred_text):
        # AT Command host returns hex of SHA256 hash of credential plaintext
        return hashlib.sha256(cred_text.encode('utf-8')).hexdigest().upper()

    def get_csr(self, sectag = 0, cn = ""):
        """Ask a device with modem to generate CSR using AT%KEYGEN.

        Returns:
            x509.CertificateSigningRequest object.
        """

        # provide attributes parameter if a custom CN is specified
        attr = f',"CN={cn}"' if len(cn) else ''

        self.at_command(f'AT%KEYGEN={sectag},2,0{attr}')

        # include the CR in OK because 'OK' could be found in the CSR string
        retval, output = self.serial_wait_for_response(b'OK\r', b'ERROR', store=b'%KEYGEN:')
        if not retval:
            raise ATKeygenException('Unable to generate private key; does it already exist for this sectag?', 9)
        elif output == None:
            raise ATKeygenException('Unable to detect KEYGEN output', 10)

        # convert the encoded blob to an actual cert
        csr_blob = str(output).split('"')[1]
        if self.verbose:
            print(local_style('CSR blob: {}'.format(csr_blob)))

        csr_bytes, _, _, _ = modem_credentials_parser.parse_keygen_output(csr_blob)

        # load and return the CSR
        return x509.load_pem_x509_csr(csr_bytes)

    def go_offline(self):
        return self.at_command('AT+CFUN=4', wait_for_result=True)

    def get_imei(self):
        self.at_command('AT+CGSN')
        retval, output = self.serial_wait_for_response('OK', 'ERROR', store='\r\n')
        if not retval:
            return None
        return output.decode("utf-8")[:IMEI_LEN]

    def get_mfw_version(self):
        self.at_command('AT+CGMR')
        retval, output = self.serial_wait_for_response('OK', 'ERROR', store='\r\n')
        if not retval:
            return None
        return output.decode("utf-8").rstrip('\r\n')

TLS_CRED_TYPES = ["CA", "SERV", "PK"]
# This chunk size can be any multiple of 4, as long as it is small enough to fit within the
# Zephyr shell buffer.
TLS_CRED_CHUNK_SIZE = 48

class TLSCredShellInterface(CredentialCommandInterface):
    def write_credential(self, sectag, cred_type, cred_text):
        # Because the Zephyr shell does not support multi-line commands,
        # we must base-64 encode our PEM strings and install them as if they were binary.
        # Yes, this does mean we are base-64 encoding a string which is already mostly base-64.
        # We could alternatively strip the ===== BEGIN/END XXXX ===== header/footer, and then pass
        # everything else directly as a binary payload (using BIN mode instead of BINT, since
        # MBedTLS uses the NULL terminator to determine if the credential is raw DER, or is a
        # PEM string). But this will fail for multi-CA installs, such as CoAP.

        # text -> bytes -> base64 bytes -> base64 text
        encoded = base64.b64encode(cred_text.encode()).decode()

        # Clear credential buffer -- If it is already clear, there may not be text feedback
        self.write_raw("cred buf clear")

        # Write the encoded credential in chunks
        chunks = math.ceil(len(encoded)/TLS_CRED_CHUNK_SIZE)
        for c in range(chunks):
            chunk = encoded[c*TLS_CRED_CHUNK_SIZE:(c+1)*TLS_CRED_CHUNK_SIZE]
            self.write_raw(f"cred buf {chunk}")
            self.serial_wait_for_response("Stored")

        # Store the buffered credential
        self.write_raw(f"cred add {sectag} {TLS_CRED_TYPES[cred_type]} DEFAULT bint")
        result, output = self.serial_wait_for_response("Added TLS credential")
        time.sleep(1)
        return result

    def delete_credential(self, sectag, cred_type):
        self.write_raw(f'cred del {sectag} {TLS_CRED_TYPES[cred_type]}')
        result, output = self.serial_wait_for_response("Deleted TLS credential", "There is no TLS credential")
        time.sleep(2)
        return result

    def check_credential_exists(self, sectag, cred_type, get_hash=True):
        self.write_raw(f'cred list {sectag} {TLS_CRED_TYPES[cred_type]}')

        # This will capture the list dump for the credential if it exists.
        result, output = self.serial_wait_for_response("1 credentials found.",
                                                       "0 credentials found.",
                                                       store=
                                                       f"{sectag},{TLS_CRED_TYPES[cred_type]}")

        if not output:
            return False, None

        if not get_hash:
            return True, None

        # Output is a comma separated list of positional items
        data = output.decode().split(",")
        hash = data[2].strip()
        status_code = data[3].strip()

        if (status_code != "0"):
            print(error_style(f"Error retrieving credential hash: {output.decode().strip()}."))
            print(error_style("Device might not support credential digests."))
            return True, None

        return True, hash

    def calculate_expected_hash(self, cred_text):
        # TLS Credentials shell returns base-64 of SHA256 hash of full credential, including NULL
        # termination.
        hash = hashlib.sha256(cred_text.encode('utf-8') + b'\x00')
        return base64.b64encode(hash.digest()).decode()

    def get_csr(self, sectag = 0, cn = ""):
        raise RuntimeError("The TLS Credentials Shell does not support CSR generation")

    def go_offline(self):
        # TLS credentials shell has no concept of online/offline. Just no-op.
        pass

    def get_imei(self):
        raise RuntimeError("The TLS Credentials Shell does not support IMEI extraction")

    def get_mfw_version(self):
        raise RuntimeError("The TLS Credentials Shell does not support MFW version extraction")
