#!/usr/bin/env python2

'''
Created on Feb 4, 2015

@author: Christophe Vandeplas <christophe@vandeplas.com>
'''

import binascii
import struct
import math

from scapy.all import *
from scapy.layers import *
from scapy.layers.netbios import *
from scapy.layers.smb import *
from scapy.error import Scapy_Exception

'''
fgrep -E -v '\taa' data/test.txt  | awk -F'\t' '{ print $2 }' | sort | uniq -c  | sort -k 2 -n  > data/test.commands.txt

# Primary and secundary commands
fgrep -E -v '\taa' data/test.txt  | awk -F'\t' '{ print $2 }'  | awk '{ print $3 " " $4 }' | sort | uniq -c
  57 07 04
  13 b5 03
  26 b5 05
  37 b5 07
   3 b5 08
 148 b5 09
  78 b5 10
 167 b5 11
  17 b5 12
   3 b5 13
  52 b5 16


receiver calculates CRC, if OK, ack with 00
CRC = X^8 + x^7 + x^4 + x^3 + x + 1  ???
CRC = 0b110011011


???
                              ##
10 08 b5 11 01 01 89 00 09 49 4e 00 80 ff ff 00 00 ff d7 00 aa aa   VT lead water temp = 0x49 = 73 C
                                                                    NT return water = 0x4e = 78 C
                                                                    TA_L = 0x00 = 0  ??
                                                                    TA_H = 0x80 = 128 = 0,5  ??
                                                                    WT = outgoing tap water? = 0xff 
                                                                    ST = service water temp = 0xff 
                                                                    vv = 0x00 = 0 heating  (1=service water)
                                                                    xx = 0x00 (always 00)
                                                                    xx = 0xFF (always FF)
                                                                    CRC 
10 08 b5 11 01 01 89 00 09 49 4d 00 80 ff ff 00 00 ff 36 00 aa aa 
10 08 b5 11 01 01 89 00 09 48 4c 00 80 ff ff 00 00 ff 7d 00 aa aa 
                              ##

                CRC ACK NN ##                      CRC
10 08 b5 11 01 00 88 00 08 76 02 0f 00 1f 10 00 80 ac 00 aa aa 
10 08 b5 11 01 00 88 00 08 74 02 0f 00 1f 10 00 80 9b 00 aa aa 
10 08 b5 11 01 00 88 00 08 50 02 0f 00 1f 10 00 80 b3 00 aa aa 
10 08 b5 11 01 00 88 00 08 4e 02 0f 00 1f 10 00 80 15 00 aa aa 
10 08 b5 11 01 00 88 00 08 4d 02 0f 00 1f 10 00 80 f4 00 aa aa 
10 08 b5 11 01 00 88 00 08 4b 02 0f 00 1f 10 00 80 ad 00 aa aa 
10 08 b5 11 01 00 88 00 08 49 02 0f 00 1f 10 00 80 9a 00 aa aa 
10 08 b5 11 01 00 88 00 08 48 02 0f 00 1f 10 00 80 4c 00 aa aa 
                           ##


'''
# 10 = examaster
# 08 = must be boiler ? tbc

def unpackHighByte(x):
    # little endian, so high byte is on the right
    return float(struct.unpack('!b', x[1])[0])

def unpackLowByte(x):
    # little endian, so low byte is on the left
    return float(struct.unpack('!B', x[0])[0])


def packSignedChar(x):
    # little endian, so high byte is on the right
    return struct.pack('!b', x)[0]

def packUnsignedChar(x):
    # little endian, so low byte is on the left
    return struct.pack('!B', x)[0]



class BCDField(ByteField):
    '''
    BCD - Binary Coded Decimal
    resolution: 1
    state: should be working fine
    '''
    def i2repr(self, pkt, x):
        return binascii.hexlify(struct.pack('b',(self.i2h(pkt, x))))


class Data1bField(Field):
    '''
    SIGNED CHAR 
    resolution: 1
    state: should be working fine

    if ((x & 80h) == 80h) //=> y negat. y = - [dec(!x) + 1]
    else y = dec(x)
    '''
    def __init__(self, name, default):
        Field.__init__ (self, name, default, "b")
    def i2repr(self, pkt, x):
        return "%f *C"%(float(self.i2h(pkt, x)))


class Data1cField(ByteField):
    '''
    CHAR / 2
    resolution: 0,5
    state: should be working fine

    y = dec(x) / 2
    Max 100
    '''
    def __init__(self, name, default):
        ByteField.__init__(self, name, default)
    def i2repr(self, pkt, x):
        # FIXME: bigger than 100 should be implemented somewhere else. Perhaps in the i2h and h2i I think.
        if self.i2h(pkt, x) > 100:
            return 'none'
        return "%.1f *C"%(self.i2h(pkt, x))
    def i2m(self, pkt, x):
        # internal 2 machine, extract after comma, place that in the low byte*256,
        # before comma, as high byte
        # FIXME double check if this is indeed correct
        return x*2
    def m2i(self, pkt, x):
        # machine 2 internal
        return (float(x)/2)


class Data2bField(Field):
    '''
    resolution: 1/256
    state: should be working fine, i2m TODO

    DATA2b contains in Low_Byte the post comma digits (in 1/256 ), the High_Byte corresponds with DATA1b.
    High_Byte DATA2b : Signed, Low_Byte DATA2b : Unsigned 
    Sample Calculation:
        if ((x & 8000h) == 8000h) //=> y negative
            y = - [dec(High_Byte(!x)) + (dec(Low_Byte(!x)) + 1) / 256]
        else //=> y positive
            y = dec(High_Byte (x)) + dec(Low_Byte (x)) / 256
    little endian

    internal: we store the value as float
    '''
    def __init__(self, name, default):
        Field.__init__(self, name, default, "2s")
    def h2i(self, pkt, x):
        return x
    def i2h(self, pkt, x):
        return x
    def i2m(self, pkt, x):
        # internal 2 machine, extract after comma, place that in the low byte*256,
        # before comma, as high byte
        # FIXME double check if this is indeed correct
        x_int = math.floor(y)
        x_comma = ( y - math.floor(y) ) * 256
        return packUnsignedChar(x_comma), packSignedChar(x_int) # FIXME this should be put in a double byte, not an array
    def m2i(self, pkt, x):
        # machine 2 internal
        return ( unpackHighByte(x) + ( unpackLowByte(x) / 256 ) )
    def any2i(self, pkt, x):
        return self.h2i(pkt,x)
    def i2repr(self, pkt, x):
        return "%.1f *C"%(self.i2h(pkt, x))
    def randval(self):
        # TODO 
        pass


class Data2cField(Field):
    '''
    SIGNED INT  = short 
    resolution: 1/16

    state: should be working fine, i2m TODO

    DATA2c contains in Low Nibble of Low Bytes the post comma digits (in 1/16).
    Sample Calculation:
        if ((x & 8000h) == 8000h) //=> y negative
            y = - [dec(High_Byte(!x)) * 16 + dec(High_Nibble (Low_Byte (!x)))
                + (dez(Low_Nibble (Low_Byte (!x))) +1 ) / 16]
        else //=> y positive
            y = dez(High_Byte(x)) * 16 + dez(High_ Nibble (Low Byte (x)))
                + dez(Low_ Nibble (Low Byte (x))) / 16
    little endian

    internal: we store the value as float
    '''
    def __init__(self, name, default):
        Field.__init__(self, name, default, "2s")
    def h2i(self, pkt, x):
        return x
    def i2h(self, pkt, x):
        return x
    def i2m(self, pkt, x):
        # internal 2 machine
        # FIXME double check if this is indeed correct
        x_int = math.floor(y)
        x_lowNibble = ( y - x_int ) * 16
        x_highByte = math.floor(x_int / 16)
        x_highNibble = x_int - ( x_highByte * 16 )
        x_lowByte = ( x_highNibble * 16 ) + x_lowNibble
        return packUnsignedChar(x_lowByte), packSignedChar(x_highByte) # FIXME this should be put in a double byte, not an array
    def m2i(self, pkt, x):
        # machine 2 internal
        intByte = struct.unpack('!B', x[0])[0]   # x[0] because little endian
        highNibble = intByte >> 4
        lowNibble = intByte - ( highNibble << 4 )
        return ( unpackHighByte(x) * 16 ) + highNibble + ( float(lowNibble) / 16 )
    def any2i(self, pkt, x):
        return self.h2i(pkt,x)
    def i2repr(self, pkt, x):
        return "%.1f *C"%(self.i2h(pkt, x))
    def randval(self):
        # TODO 
        pass







class EBus(Packet):
    name = "eBUS"

    ebus_primary_commands = {
                            0x07: "0x07 - System Data Commands",
                            0xb5: "0xB5 - Bulex Commands"
                             }
    ebus_secundary_commands = {
                 0x07: {0x00: "Date/Time Message of an eBUS Master",
                        0x01: "Setting Date/Time",
                        0x02: "Setting Outside Temperature",
                        0x03: "Query of supported Commands",
                        0x04: "Identification",
                        0x05: "Query of supported Commands",
                        0x06: "Inquiry of Existence",
                        0xFF: "Sign of Life"},
                 0xb5: {0x03: "0x03 Unknown Command",
                        0x04: "Get Operational Data",
                        0x05: "Set Operational Data",
                        0x06: "0x06 Unknown Broadcast 2",
                        0x07: "0x07 Unknown Command",
                        0x08: "0x08 Unknown Command",
                        0x09: "Get or Set Device Configuration",
                        0x10: "Operational Data from Room Controller to Burner Control Unit",
                        0x11: "Operational Data of Burner Control Unit to Room Control Unit",
                        0x12: "0x12 Unknown Command",
                        0x13: "0x13 Unknown Command",
                        0x16: "Broadcast Service",
                        
                        }
                 }

    fields_desc = [ 
                    XByteField("QQ", None), # Source Address
                    XByteField("ZZ", None), # Destination Address
                    ByteEnumField("PB", None, ebus_primary_commands), # Primary Command 
                    MultiEnumField("SB", None, ebus_secundary_commands, # Secundary Command
                                      depends_on=lambda x:x.PB,
                                      fmt="B"),
                    ByteField("NN", 0x00) # Length of data
                    
    ]

class EBusBulexOpDataRoomControlBurnerControl(Packet):
    '''
    Seems to be related to the temperature of the boiler

    state: work in progress
    '''
    fields_desc = [
                    XByteField("xx1", 0x00),# always 0x00
                    XByteField("xx2", 0x00),# always 0x00
                    Data1cField("LT", None), # Lead water target temperature
                                            # lots of 0 C
                                            # then from 50 to 77,5 C
                    Data1cField("ST", None), # Service water target temperature
                                            # 50 C
                    XByteField("xx3", 0xFF),# always 0xff
                    XByteField("xx4", 0xFF),# always 0xff
                    XByteField("xx5", 0x00),# 0x00 or 0x01
                    XByteField("xx6", 0xFF),# always 0xff
                    XByteField("xx7", 0x00),# always 0x00
                    XByteField("CRC", None), # CRC

                    XByteField("ACK", 0x00),
                    ByteField("NN2", 0x01), # Length of data, 1
                    ByteField("zz", 0x01), # acknowledge? always 1
                    XByteField("CRC", None),
                    XByteField("ACK", 0x00)
    ]


class EBusBulexOpDataBurnerControltoRoomControl(Packet):
    '''
    state: work in progress
    '''
    fields_desc = [
                    ByteField("BLK_NUM", 0x01),
                    XByteField("CRC", None), # CRC
                    XByteField("ACK", 0x00),
                    ByteField("NN", 0x00) # Length of data
    ]


class EBusBulexOpDataBurnerControltoRoomControl0(Packet):
    '''
    state: TODO unknown
    '''
    fields_desc = [
                    XByteField("xx1", None), # many values, probably temperature
                                             # 0x00 up to 0xff 
                    XByteField("xx2", None), # 447         xx2       = 0x1
                                             # 299         xx2       = 0x2
                                             # 947         xx2       = 0x3
                                             # 320         xx2       = 0x4
                    XByteField("xx3", None), #1009         xx3       = 0x10
                                             #   1         xx3       = 0x4
                                             # 315         xx3       = 0xc
                                             # 331         xx3       = 0xd
                                             #  71         xx3       = 0xe
                                             # 286         xx3       = 0xf
                    XByteField("xx4", None), # many values, probably temperature,
                                             # 0x00 up to 0x50 
                                             # mainly 0x1d t0 0x2d
                    XByteField("xx5", None), #  529         xx5       = 0x1f
                                             #    3         xx5       = 0x2
                                             #    1         xx5       = 0x37
                                             # 1309         xx5       = 0x4
                                             #   39         xx5       = 0x7
                                             #  132         xx5       = 0x8
                    XByteField("xx6", None), #  661         xx6       = 0x10
                                             #    1         xx6       = 0x4
                                             #   42         xx6       = 0x8
                                             # 1309         xx6       = 0xf
                    XByteField("xx7", None), # always 0x00, once 0x0f
                    XByteField("xx8", None), # 0x00, 0x80, 0x81, 0x82
                    XByteField("CRC", None),
                    XByteField("ACK", 0x00)
    ]


class EBusBulexOpDataBurnerControltoRoomControl1(Packet):
    '''
    state: work in progress, needs to be tested with checked numbers
    '''
    fields_desc = [
                    Data1cField("VT", 0xff), # Lead Water temperature
                    Data1cField("NT", 0xff), # Return water temperature
                    Data2bField("TA", 0x8000), # Outside temperature
                    Data1cField("WT", 0xff), # Lead Water temperature to boiler ?
                    Data1cField("ST", 0xff), # Boiler temperature ?
                    ByteEnumField("vv", None, { 0: 'heating', 1: 'service water'}),
                    XByteField("xx1", 0x00),
                    XByteField("xx2", 0xFF),
                    XByteField("CRC", None),
                    XByteField("ACK", 0x00)
    ]

class EBusBulexOpDataBurnerControltoRoomControl2(Packet):
    '''
    state: TODO unknown
    '''
    fields_desc = [
                    XByteField("xx1", None), # 0x02, 0x03
                    XByteField("xx2", None), # always 0x14
                    XByteField("xx3", None), # always 0x96
                    XByteField("xx4", None), # always 0x5a
                    XByteField("xx5", None), # always 0x5a
                    XByteField("CRC", None),
                    XByteField("ACK", 0x00)
    ]

class EBusBulexSetOpData(Packet):
    '''
    state: TODO unknown
    '''
    fields_desc = [
                    ByteEnumField("TB", None, { 0x5c: '0x5c Unknown',
                                                # below = From the Vaillant reverse engineering
                                                0x01: 'SetTargetTemperature',
                                                0x02: 'SetOperationMode',
                                                0x09: 'SetTimerProgram',
                                                0x0A: 'SetNightTemperatureHK1',
                                                0x0B: 'SetHeatingTemperatiureRatio',
                                                0x11: 'SwitchSWLoadingPunpDelay',
                                                0x12: 'SetSWLoadingPumpDelay',
                                                0x13: 'SwitchLegionnairsDiseaseProtection',
                                                0x14: 'SwitchParallelLoading',
                                                0x1A: 'SetCylinderMaxTempSolar1',
                                                0x1B: 'SetCylinderHysteresisSolar1',
                                                0x1C: 'SetOutsideTempCorr',
                                                0x1D: 'SetCylinderMaxTempSolar2',
                                                0x1E: 'SetCylinderHysteresisSolar2',
                                                0x20: 'ResetSolarYieldKOL1',
                                                0x21: 'SetSolarFlowRate',
                                                0x23: 'SwitchEDPumpControl',
                                                0x27: 'HeatingStatus',
                                                0x2B: 'SetSystemParameters',
                                                0x2D: '(unknown)',
                                                0x3C: 'VR81RemoteControlUnitForVRC'
                                            })
    ]

class EBusBulexGetOrSetDeviceConf(Packet):
    '''
    state: TODO unknown
    '''
    fields_desc = [
                    ByteEnumField("DB", None, { 0x0e: '0x0e unknown',
                                                0x29: '0x29 unknown'
                                            })
    ]


class EBusBulexBroadcast(Packet):
    '''
    state: should be working fine
    '''
    fields_desc = [
                    ByteEnumField("TB", None, { 0x00: 'Date/Time',
                                                0x01: 'Outside temperature'
                                            })
    ]


class EBusBulexBroadcastOutsideTemperature(Packet):
    '''
    state: should be working fine
    '''
    fields_desc = [
                    Data2bField("TA", None),
                    XByteField("CRC", None)
    ]


class EBusBulexBroadcastDateTime(Packet):
    '''
    state: should be working fine
    '''
    fields_desc = [
                    BCDField("ss", None),  # Sec
                    BCDField("min", None), # Min
                    BCDField("hh", None),  # Hour
                    BCDField("dd", None),  # Day
                    BCDField("mm", None),  # Month
                    BCDField("ww", None),  # Weekday
                    BCDField("yy", None),  # Year ??
                    XByteField("CRC", None)
    ]


class EBusBulexUnknown03(Packet):
    '''
    state: TODO unknown

       1 This packet:  10 08 b5 03 02 00 01 2f 00 0a ff ff ff b5 09 03 29 64 00 8d 00 03 64 00 00 0d 00  
       1 This packet:  10 08 b5 03 02 00 01 2f 00 0a ff ff ff ff ff  
     340 This packet:  10 08 b5 03 02 00 01 2f 00 0a ff ff ff ff ff ff ff ff ff ff 0f 00  
    '''
    fields_desc = [
                    XByteField("xx1", None),
                    XByteField("xx2", None),
                    XByteField("CRC1", None),
                    XByteField("ACK", 0x00),
                    
    ]


class EBusBulexUnknown07(Packet):
    '''
    state: TODO unknown

     325 This packet:  10 08 b5 07 01 08 0f 00 02 64 00 41 00  
     672 This packet:  30 15 b5 07 01 08 0b 00 02 fa 00 0d 00  
    '''
    fields_desc = [
                    XByteField("xx1", None), # 0x08
                    XByteField("CRC1", None),
                    XByteField("ACK", 0x00),
                    ByteField("NN", None), # length ?
                    XByteField("xx3", None),
                    XByteField("xx4", None),
                    XByteField("CRC2", None),
                    XByteField("ACK", 0x00)
    ]

class EBusBulexUnknown12(Packet):
    '''
    state: TODO unknown

     332 This packet:  03 64 b5 12 02 02 00 66  
     164 This packet:  03 64 b5 12 02 02 fe 98  
    '''
    fields_desc = [
                    XByteField("xx1", None),# always 0x02
                    XByteField("xx2", None),# 0x00 or 0xfe
                    XByteField("CRC", None), # CRC ?
    ]


class EBusIdentification(Packet):
    '''
    state: TODO unknown

      68 This packet:  10 08 07 04 00 17 00 0a b5 42 41 49 30 30 05 01 33 02 4e 00  
     201 This packet:  10 18 07 04 00 ad  
     201 This packet:  10 38 07 04 00 42  
     201 This packet:  10 78 07 04 00 07  
     198 This packet:  10 bb 07 04 00 2a  
     198 This packet:  10 bc 07 04 00 2b  
     201 This packet:  10 f8 07 04 00 8d 
    '''
    fields_desc = [
                    XByteField("CRC", None),
                    XByteField("ACK", 0x00),
                    ByteField("NN", 0x00), # Length of data
                    XByteField("HH", 0xb5), # 0xb5 = Vaillant / Bulex
                    StrFixedLenField("gg", "", 5), # Device ID: "BAI00"
                    BCDField("vvs1", 0x00), #FIXME , this + next = SW version
                    BCDField("vvs2", 0x00), 
                    BCDField("vvh1", 0x00), #FIXME , this + next = HW version
                    BCDField("vvh2", 0x00), 
                    XByteField("CRC", None),
                    XByteField("ACK", 0x00)
    ]



# Working layers
bind_layers(EBus, EBusBulexBroadcast, PB=0xb5, SB=0x16)
bind_layers(EBusBulexBroadcast, EBusBulexBroadcastDateTime, TB=0x00)
bind_layers(EBusBulexBroadcast, EBusBulexBroadcastOutsideTemperature, TB=0x01)


# Work in progress
bind_layers(EBus, EBusIdentification, PB=0x07, SB=0x04)
bind_layers(EBus, EBusBulexOpDataRoomControlBurnerControl, PB=0xb5, SB=0x10)
bind_layers(EBus, EBusBulexOpDataBurnerControltoRoomControl, PB=0xb5, SB=0x11)
bind_layers(EBus, EBusBulexSetOpData, PB=0xb5, SB=0x05)
bind_layers(EBus, EBusBulexGetOrSetDeviceConf, PB=0xb5, SB=0x09)
bind_layers(EBus, EBusBulexUnknown03, PB=0xb5, SB=0x03)
bind_layers(EBus, EBusBulexUnknown07, PB=0xb5, SB=0x07)
bind_layers(EBus, EBusBulexUnknown12, PB=0xb5, SB=0x12)
bind_layers(EBusBulexOpDataBurnerControltoRoomControl, EBusBulexOpDataBurnerControltoRoomControl0, BLK_NUM=0)
bind_layers(EBusBulexOpDataBurnerControltoRoomControl, EBusBulexOpDataBurnerControltoRoomControl1, BLK_NUM=1)
bind_layers(EBusBulexOpDataBurnerControltoRoomControl, EBusBulexOpDataBurnerControltoRoomControl2, BLK_NUM=2)



#data = b'\x10\x08\xb5\x11\x01\x00\x88\x00\x08\x5d\x02\x0f\x00\x1f\x10\x00\x80\xd7\x00\xaa\xaa'
#data = b"\x10\x08\xb5\x11\x01\x01\x89\x00\x09\x4e\x54\x00\x80\xff\xff\x00\x00\xff\xfa\x00\xaa\xaa"
#data = b'\x10\x18\x07\x04\x00\xad\xaa'

# packet = b'\x10\xfe\xb5\x16\x03\x01\x80\x02\xd5'
# e = EBus(packet)
# e.show()
# print ("This packet: "), 
# for i in packet:
#                     print (binascii.hexlify(i)),
#exit()

# TODO : make sure that 

def EBusProcessStream(f):
    packet_list = []
    while True:
        byte = f.read(1)
        if not byte:  # end of file
            break     # stop processing
        if byte == b'\xaa':  # 0xaa is a SYN
                             # this means that either there is no data
                             # or that the data stream is finished
            if packet_list:
                # Process packet
                e = EBus(''.join(packet_list))
                if e.haslayer(EBusBulexBroadcastOutsideTemperature):
                   
                # if not e.haslayer(EBusBulexBroadcast) and \
                #    not e.haslayer(EBusBulexBroadcastDateTime) and \
                #    not e.haslayer(EBusBulexBroadcastOutsideTemperature) and \
                #    not e.haslayer(EBusBulexOpDataBurnerControltoRoomControl2) and \
                #    not e.haslayer(EBusBulexOpDataBurnerControltoRoomControl1) and \
                #    not e.haslayer(EBusBulexOpDataBurnerControltoRoomControl0) and \
                #    not e.haslayer(EBusBulexSetOpData) and \
                #    not e.haslayer(EBusBulexGetOrSetDeviceConf) and \
                #    not e.haslayer(EBusBulexUnknown07) and \
                #    not e.haslayer(EBusBulexOpDataRoomControlBurnerControl) and \
                #    not e.haslayer(EBusBulexUnknown12) and \
                #    not e.haslayer(EBusBulexUnknown03) \
                #    :

                    e.show()
                    # for the fun, print it on the screen
                    print ("")
                    print ("This packet: "), 
                    for i in packet_list:
                        print (binascii.hexlify(i)),
                    print (" ")
                    print ("")
                    print ("")
            packet_list = []
            continue  # jump to next byte read

        # it's not a SYN, nor the end of the stream (also SYN)
        # so we should continue reading into our packet
        packet_list.append(byte)
    pass



# read out from a file
filename = 'data/data.short.bin'
filename = 'data/data.bin'
with open(filename, 'rb') as f:
    EBusProcessStream(f)


# # read out from the serial bus
# import serial
# serial_dev='/dev/tty.usbmodem1411'
# serial_baudrate=2400
# with serial.Serial(serial_dev, serial_baudrate) as f:
#     EBusProcessStream(f)


# packet_list = b'\x10\x08\xb5\x11\x01\x01\x89\x00\x09\x7d\x72\x00\x80\xff\xff\x01\x00\xff\x39\x00'
# e = EBus(packet_list)
# e.show()
# print ("")
# print ("This packet: 00 80 : "), 
# for i in packet_list:
#     print (binascii.hexlify(i)),
# print ("")








# Test case for DATA1b
# x = b'\x00'
# y = 0
# x = b'\x01'
# y = 1
# x = b'\x7f'
# y = 127
# x = b'\x81'
# y = -127
# x = b'\x80'
# y = -128

# y = float(struct.unpack('!b', x)[0])
# print y

# Test case for DATA2b
# x = b'\x00\x80'
# x = b'\x00\x00'  # 0
# x = b'\x00\x01'  
# y= 0.00390625
# x = b'\xff\xff'  
# y= - 0.00390625
# x = b'\xff\x00'  
# y= -1
# x = b'\x80\x00'  
# y = -128
# x = b'\x80\x01'  # -127,996
# x = b'\x7f\xff'  # 127,996

# y = ( unpackHighByte(x) + unpackLowByte(x) / 256 )


# # # Test case for DATA2c
# x = b'\x00\x00'
# y = 0
# x = b'\x00\x01'
# y = float(1)/16          # 0,0625
# x = b'\xff\xff'
# y = -float(1)/16       # -0,0625
# x = b'\xff\xf0'
# y = -1
# x = b'\x80\x00'
# y = -2048
# x = b'\x80\x01'
# y = -2047.9
# x = b'\x7f\xff'
# y = 2047.9375   # 0,9375


# # intByte = struct.unpack('!B', x[0])[0]   # x[0] because little endian
# # highNibble = intByte >> 4
# # lowNibble = intByte - ( highNibble << 4 )
# # y = ( unpackHighByte(x) * 16 ) + highNibble + ( float(lowNibble) / 16 )
# # print (y)

# x_int = math.floor(y)
# x_lowNibble = ( y - x_int ) * 16
# x_highByte = math.floor(x_int / 16)
# x_highNibble = x_int - ( x_highByte * 16 )
# x_lowByte = ( x_highNibble * 16 ) + x_lowNibble

# x = packSignedChar(x_highByte), packUnsignedChar(x_lowByte)

 

# scapy.utils.hexdump (packSignedChar(x_highByte))
# scapy.utils.hexdump (packUnsignedChar(x_lowByte))




