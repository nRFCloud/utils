import time
from pynrfjprog import LowLevel

CRLF = '\r\n'

# Accumulates RTT characters until lines are completed
rtt_tail = ""

def send_rtt(api, tx_data):
    for i in range(0, len(tx_data), 12):
       api.rtt_write(channel_index=0, msg=tx_data[i:i+12])
       time.sleep(0.01)

# Accumulate new characters to the rtt tail
def accumulate_lines_rtt(api):
    global rtt_tail
    rx_new = api.rtt_read(channel_index=0, length=4096)
    if rx_new:
        rx = rx + rx_new

# Attempt to take a line from the rtt tail
def take_line_rtt(api):
    global rtt_tail
    lines = rtt_tail.splitlines(keepends=True)
    if len(lines) > 1:
        # Remove first line from rtt_tail, return it.
        rtt_tail = "".join(lines[1:])
        return lines[0]
    return None

# Clear the rtt tail. Called by functions in this interface that directly read RTT without
# accumulating it, or otherwise invalidate the RTT tail.
def clear_rtt_tail():
    global rtt_tail
    rtt_tail = ""

# Continually accumulate rtt chars until we either timeout, or successfully take a line.
def readline_rtt(api, timeout_s):
    global rtt_tail
    deadline = time.time() + timeout_s
    rx = ''
    while time.time() < deadline:
        accumulate_lines_rtt(api)
        line = take_line_rtt(api)
        if line is not None:
            return line
        time.sleep(0.1)
    return None

# Continually accumulate rtt lines until the timeout is reached, or an AT status is printed
def readlines_at_rtt(api, timeout_s):
    deadline = time.time() + timeout_s
    lines = []

    while time.time() < deadline:
        line = readline_rtt(api, deadline - time.time())
        lines.append(line)
        if line.strip() == 'OK' or line.strip() == 'ERROR':
            break

    if time.time() >= deadline:
        print('RTT read timeout')

    return lines

def read_string_rtt(api, expected_str, timeout_s):
    elapsed_s = 0
    rx = ''
    clear_rtt_tail()

    while elapsed_s < timeout_s:
        rx_new = api.rtt_read(channel_index=0, length=4096)
        if rx_new:
            rx = rx + rx_new

            if rx:
                rx_lines = rx.splitlines(keepends=True)
                last_line = rx_lines[-1]

                if CRLF not in last_line:
                    # partial line, save for next read
                    rx = last_line
                else:
                    rx = ''

                for line in rx_lines:
                    if expected_str in line:
                        return True

        time.sleep(0.1)
        elapsed_s = elapsed_s + 0.1

    print('RTT read timeout')
    return False

def enable_at_cmds_mosh_rtt(api):
    MOSH_TERM = 'mosh:~$ '
    AT_CMD_MODE = 'at_cmd_mode start' + CRLF
    clear_rtt_tail()

    found = read_string_rtt(api, MOSH_TERM, 1)
    if not found:
        # send a CRLF and read again
        send_rtt(api, CRLF)
        found = read_string_rtt(api, MOSH_TERM, 1)
        if not found:
            print('mosh terminal not detected')
            return False

    # enable AT command mode
    send_rtt(api, f'at {AT_CMD_MODE}')
    found = read_string_rtt(api, AT_CMD_MODE, 1)
    if not found:
        # send a CRLF
        send_rtt(api, CRLF)
        time.sleep(0.2)
        api.rtt_read(channel_index=0, length=4096)

        # try command once more
        send_rtt(api, f'at {AT_CMD_MODE}')
        found = read_string_rtt(api, AT_CMD_MODE, 1)

    return found

def reset_device(snr):
    api = LowLevel.API(LowLevel.DeviceFamily.UNKNOWN)
    api.open()
    clear_rtt_tail()

    # Connect to and identify device
    if snr is None:
        api.connect_to_emu_without_snr()
    else:
        api.connect_to_emu_with_snr(snr)

    family = api.read_device_family()
    api.select_family(family)

    api.sys_reset()
    api.go()
    api.disconnect_from_emu()
    api.close()

    return True

def connect_and_program(snr, hex_path):

    if not hex_path:
        return False

    clear_rtt_tail()

    api = LowLevel.API(LowLevel.DeviceFamily.UNKNOWN)
    api.open()

    # Connect to and identify device
    if snr is None:
        api.connect_to_emu_without_snr()
    else:
        api.connect_to_emu_with_snr(snr)

    family = api.read_device_family()
    api.select_family(family)

    if not program_hex_rtt(api, hex_path):
        return False

    api.sys_reset()
    api.go()
    api.disconnect_from_emu()
    api.close()

    return True

def program_hex_rtt(api, hex_path):
    if hex_path:
        try:
            print('Erasing...')
            api.erase_file(hex_path)

            print('Programming...')
            api.program_file(hex_path)

            print('Verifying...')
            api.verify_file(hex_path)

            print('Successfully programmed device')
            api.sys_reset()
            api.go()
            return True
        except LowLevel.APIError:
            print('Failed to program device')

    return False

def connect_rtt(snr=None, hex_path=''):
    api = LowLevel.API(LowLevel.DeviceFamily.UNKNOWN)
    api.open()
    clear_rtt_tail()

    # Connect to and identify device
    if snr is None:
        api.connect_to_emu_without_snr()
    else:
        api.connect_to_emu_with_snr(snr)

    family = api.read_device_family()
    api.select_family(family)

    if hex_path:
        if not program_hex_rtt(api, hex_path):
            return None
    else:
        api.sys_reset()
        api.go()

    api.rtt_start()

    retry_cnt = 5
    while not api.rtt_is_control_block_found() and retry_cnt > 0:
        time.sleep(0.5)
        retry_cnt = retry_cnt - 1

    return api
