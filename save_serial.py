

import serial

serial_dev='/dev/tty.usbmodem1411'
serial_baudrate=2400
ser = serial.Serial(serial_dev, serial_baudrate)

with open('data/ebus-data.bin', 'wb', 100) as fb:
    while True:
        data = ser.read()
        #print(data)
        fb.write(data)


