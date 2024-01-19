from enum import Enum
from abc import ABC, abstractmethod
from cli_helpers import local_style, error_style
import time
import modem_credentials_parser

import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

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
    def _parse_sha(self, cmng_result_str):
        # Example AT%CMNG response:
        #   %CMNG: 123,0,"2C43952EE9E000FF2ACC4E2ED0897C0A72AD5FA72C3D934E81741CBD54F05BD1"
        # The first item in " is the SHA.
        try:
            return cmng_result_str.decode().split('"')[1]
        except (ValueError, IndexError):
            print(error_style(f'Could not parse credential hash: {cmng_result_str}'))
            return None

    def at_command(self, at_command, wait_for_result=False):
        """Write an AT command to the command interface. Optionally wait for OK"""

        # AT commands are written directly as-is with the ATCommandInterface:
        self.write_raw(at_command)

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

    def get_csr(self, sectag = 0, cn = ""):
        """Ask a device with modem to generate CSR using AT%KEYGEN.

        Returns:
            CSR as X509Req object.
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

        modem_credentials_parser.parse_keygen_output(csr_blob)

        # load and return the CSR
        csr_bytes = modem_credentials_parser.csr_pem_bytes
        try:
            return OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_bytes)
        except OpenSSL.crypto.Error:
            raise RuntimeError("Error loading CSR")

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
