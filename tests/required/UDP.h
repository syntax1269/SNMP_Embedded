#ifndef UDP_h
#define UDP_h

#ifdef COMPILING_TESTS

#include "tests/required/IPAddress.h"
#include <stddef.h>

class UDP {
  public:
    /* v3.4.4 (P1): methods virtual so a test subclass can feed packets
     * through SNMPAgent::loop() (real hardware classes already dispatch). */
    virtual uint8_t begin(int){ return 1; }
    virtual int parsePacket(){ return 0; }
    virtual void beginPacket(IPAddress, uint16_t){}
    virtual int endPacket(){ return 1; }
    virtual void write(uint8_t*, size_t){}
    virtual void stop(){}
    virtual int read(uint8_t*, int){ return 0; }
    virtual IPAddress remoteIP(){return IPAddress();}
    virtual int remotePort(){return 0;}

};

#endif
#endif
