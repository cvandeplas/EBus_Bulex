

import serial

serial_dev='/dev/tty.usbmodem1411'
serial_baudrate=2400
ser = serial.Serial(serial_dev, serial_baudrate)

fb = open('data/data.bin', 'bw')

while True:
    data = ser.read()
    #print(data)
    fb.write(data)


