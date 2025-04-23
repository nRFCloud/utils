import nrfcloud_utils.comms as comms

if __name__ == '__main__':
    serial = comms.Comms(rtt=True)
    serial.write_line("at AT+CGMR")
    while True:
        line = serial.read_line()
        if line:
            print(line)
            if "OK" in line:
                break
            if "ERROR" in line:
                break
        else:
            break
