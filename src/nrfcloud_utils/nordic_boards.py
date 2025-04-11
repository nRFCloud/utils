from serial.tools import list_ports
import serial
from collections import defaultdict
import sys
import time
import coloredlogs, logging

logger = logging.getLogger(__name__)

serial_timeout = 1

# Some Nordic boards have their main serial port on the second interface.
# Serial number prefix, display name, main_port
usb_patterns = [
    (r"THINGY91", "Thingy:91", 0),
    (r"PCA20035", "Thingy:91", 0),
    (r"0009600", "nRF9160-DK", 0),
    (r"0009601", "nRF5340-DK", 1),
    (r"0010500", "nRF5340-DK", 1),
    (r"0010507", "nRF7002-DK", 1),
    (r"0010509", "nRF9161-DK", 0),
    (r"0010510", "nRF9131-EK", 0),
    (r"0010511", "nRF54H20-DK", 0),
    (r"0010512", "nRF9151-DK", 0),
    (r"0010550", "Thingy:91 X", 0),
    (r"0010551", "Thingy:91 X", 0),
    (r"0010513", "Thingy:91 X", 0),
    (r"0010577", "nRF54L15-DK", 1),
    (r"NRFBLEGW", "nRF Cloud Gateway", 0),
]

# HWIDs look different on different platforms:
# Linux: 'USB VID:PID=1366:1059 SER=001051216197 LOCATION=3-12.1.3.2.1.4:1.0'
# MacOS: 'USB VID:PID=1366:1059 SER=001051246141 LOCATION=0-1.4.2.3'
# Windows: [(1, 'USB VID:PID=1366:1059 SER=001057731013'), (2, 'USB VID:PID=1366:1059 SER=001057731013 LOCATION=1-21:x.2')]

def get_connected_nordic_boards():
    """
    Get a list of connected Nordic boards. The function returns a list of
    serial ports that match the USB patterns defined above. The function
    uses the serial.tools.list_ports module to list the connected serial
    ports and filter them based on the USB patterns.
    """
    pattern = r'SER=(' + r'|'.join(name[0] for name in usb_patterns) + r')'
    ports = list(sorted(list_ports.grep(pattern)))
    nordic_boards = defaultdict(list)
    for port in ports:
        # Get serial number from hwid, because port.serial_number is not always available
        serial=[x[4:] for x in port.hwid.split(' ') if x.startswith('SER=')][0]
        nordic_boards[serial].append(port)
    main_ports = []
    for serial, ports in nordic_boards.items():
        for pattern, name, main_port in usb_patterns:
            if serial.startswith(pattern):
                main_ports.append((name, serial, ports[main_port]))
                break
    return main_ports

def ask_for_port(list_all):
    """
    Show a list of ports and ask the user for a choice, unless user specified
    a specific port on the command line. To make selection easier on systems
    with long device names, also allow the input of an index.
    """

    # if list_all is True, show all ports, not just Nordic devices
    if list_all:
        ports = list_ports.comports()
        for i, port in enumerate(ports):
            print(f'  {i}: {port.hwid}')
            port = input('--- Enter port index: ')
            index = int(port)
            if not 0 <= index < len(ports):
                logger.error('--- Invalid index!')
                continue
            return ports[index]

    # Get a list of connected Nordic boards
    ports = get_connected_nordic_boards()

    if len(ports) == 0:
        logger.error('No device found')
        return None
    if len(ports) == 1:
        name, serial, port = ports[0]
        return port.device
    while True:
        for i, (name, serial, _) in enumerate(ports):
            print(f'  {i} {name}: {serial}')
        port = input('--- Enter port index: ')
        index = int(port)
        if not 0 <= index < len(ports):
            logger.error('--- Invalid index!')
            continue
        name, serial, port = ports[index]
        return port.device

def get_serial_port(port, baud, xonxoff, rtscts, dsrdtr):
    try:
        ser = serial.Serial(port, baud, xonxoff= xonxoff, rtscts=rtscts,
                        dsrdtr=dsrdtr, timeout=serial_timeout)
        ser.reset_output_buffer()
        ser.write(b'\r\n')
        time.sleep(0.2)
        ser.reset_input_buffer()
    except serial.serialutil.SerialException:
        logger.error('Port could not be opened; not a device, or open already.')
        sys.exit(1)
    return ser
