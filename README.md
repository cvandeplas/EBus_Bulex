EBus Bules
=============
Current research on the EBus protocol implementation by Bulex.

Af first sight it seems that the Bulex implementation ressembles a lot the one from Vaillant.

Great documentation here, but not all applicable for Bulex: 

* http://ebus.webhop.org


How to use
==========
This project is still in very very early state and is actively developed.

It uses [Scapy](http://www.secdev.org/projects/scapy/) for interpreting the packets.

Right now we are trying to interprete the whole packet, request and response, as one packet. A complete packet starts after a 0xaa and also ends with a 0xaa.

The timestamp is not based on the real time of the system, however it uses the time that is sent out every minute on the bus. This allows us to post-process data that has been saved in a file, while still maintaining correct timestamps. The (minor) disadvantages of this is that we only have a precision up to a minute, and that the clock must be set correctly on the master device.

In a later stage, when above is more or less stable, the FSM functionality of Scapy could be used to distinguish between request and response. Refactoring to this concept will probably make injecting packets a lot easier. 


License
=======
* License: AGPL v3 - http://www.gnu.org/copyleft/gpl.html 
* Copyright: Christophe Vandeplas <christophe@vandeplas.com>