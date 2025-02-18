from enum import Enum
from abc import ABC, abstractmethod
from cli_helpers import local_style, error_style
from serial_interface import SerialInterfaceGeneric
import math
import time
import modem_credentials_parser
import base64
import hashlib

import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

IMEI_LEN = 15

class CredentialCommandInterface(ABC):
    def __init__(self, serial_interface, verbose):
        """Initialize a Credentials Command Interface

        Args:
            serial_interface: An instance of SerialInterface to which commands will be written and
                              from which responses or prompts will be read.
            verbose: Whether or not to operate in verbose mode.
        """

        self.sif = serial_interface
        self.verbose = verbose

    def write_raw(self, command):
        """Write a raw line directly to the serial interface."""
        self.sif.write_line(command)

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
            result, output = self.sif.wait_for_success_or_fail(b'OK', b'ERROR')
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
        retval, res = self.sif.wait_for_success_or_fail(b'OK', b'ERROR', capture=b'%CMNG')
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
            CSR as X509Req object.
        """

        # provide attributes parameter if a custom CN is specified
        attr = f',"CN={cn}"' if len(cn) else ''

        self.at_command(f'AT%KEYGEN={sectag},2,0{attr}')

        # include the CR in OK because 'OK' could be found in the CSR string
        retval, output = self.sif.wait_for_success_or_fail(b'OK\r', b'ERROR', capture=b'%KEYGEN:')
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
        retval, output = self.sif.wait_for_success_or_fail('OK', 'ERROR', capture='\r\n')
        if not retval:
            return None
        return output.decode("utf-8")[:IMEI_LEN]

    def get_mfw_version(self):
        self.at_command('AT+CGMR')
        retval, output = self.sif.wait_for_success_or_fail('OK', 'ERROR', capture='\r\n')
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
            self.sif.wait_for_success_or_fail("Stored")

        # Store the buffered credential
        self.write_raw(f"cred add {sectag} {TLS_CRED_TYPES[cred_type]} DEFAULT bint")
        result, output = self.sif.wait_for_success_or_fail("Added TLS credential")
        time.sleep(1)
        return result

    def delete_credential(self, sectag, cred_type):
        self.write_raw(f'cred del {sectag} {TLS_CRED_TYPES[cred_type]}')
        result, output = self.sif.wait_for_success_or_fail("Deleted TLS credential",
                                                           "There is no TLS credential")
        time.sleep(2)
        return result

    def check_credential_exists(self, sectag, cred_type, get_hash=True):
        self.write_raw(f'cred list {sectag} {TLS_CRED_TYPES[cred_type]}')

        # This will capture the list dump for the credential if it exists.
        result, output = self.sif.wait_for_success_or_fail("1 credentials found.",
                                                           "0 credentials found.",
                                                           capture=
                                                           f"{sectag},{TLS_CRED_TYPES[cred_type]}")

        if not output:
            return False, None

        if not get_hash:
            return True, None

        # Output is a comma separated list of positional items
        data = output.split(",")
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

    def read_block(self):
        """Parses base-64 payloads formatted like this:
        #CSH: BEGA1UEAwwKZ190
        #CSH: yqGSM49AgEGCCqG
        #CSH: pZf2Yg=
        #CSH-END
        """

        # Scan for block output with prefix `#CSH: `, stopping when `#CSH-END` is encountered.
        result, output = self.sif.wait_for_pattern(["^#CSH-END\s*$"], ["^#CSH: "], regex=True)
        if result == -1 or len(output) == 0:
            print(error_style(f"Could not parse block output"))
            return None

        # Remove prefixes and join lines
        return "\n".join(line.strip().split("#CSH: ")[1] for line in output)

    def get_csr(self, sectag = 0, cn = ""):
        # CN is not optional for the TLS Credentials Shell
        if len(cn) == 0:
            print(error_style(f"The TLS Credentials Shell requires a Common Name for CSR."))

        self.write_raw(f'cred csr {sectag} default "CN={cn}" default')
        self.sif.wait_for_success_or_fail("CSR generated", "TODO")

        # TODO: handle failure

        csr_b64 = self.read_block()
        csr_bytes = base64.b64decode(csr_b64)

        try:
            return OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, csr_bytes)
        except OpenSSL.crypto.Error:
            raise RuntimeError("Error loading CSR")

    def go_offline(self):
        # TLS credentials shell has no concept of online/offline. Just no-op.
        pass

    def get_imei(self):
        raise RuntimeError("The TLS Credentials Shell does not support IMEI extraction")

    def get_mfw_version(self):
        raise RuntimeError("The TLS Credentials Shell does not support MFW version extraction")
