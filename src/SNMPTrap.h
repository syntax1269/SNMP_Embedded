#ifndef SNMPTrap_h
#define SNMPTrap_h

#include "include/ValueCallbacks.h"
#include "include/defs.h"
#include "include/SNMPPacket.h"

#ifdef COMPILING_TESTS
	#include "tests/required/IPAddress.h"
	#include "tests/required/UDP.h"
#else
	#include <Arduino.h>
	#include "IPAddress.h"
	
	#if defined(ESP8266) || defined(ESP32)
		#include <WiFiUdp.h>
	#else
		#include "Udp.h"
	#endif
#endif

#if SNMP_NO_TRAPS
/* SNMP_NO_TRAPS: the real class is compiled out. Any instantiation fails
 * right here with a message naming the flag — loud, never silent. */
class SNMPTrap {
  public:
    template <typename... Args>
    SNMPTrap(Args...){
        static_assert(sizeof...(Args) == 0 && !sizeof...(Args),
            "SNMP_NO_TRAPS is defined (global build flag): the trap/inform API "
            "is compiled out of this build. Remove -DSNMP_NO_TRAPS to send "
            "traps/informs, or remove the trap code from the sketch.");
    }
};
#else
class SNMPTrap : public SNMPPacket {
  public:
    SNMPTrap(const char* community, SNMP_VERSION version){
        this->setVersion(version);
        this->setPDUType(Trapv2PDU);
        this->setCommunityString(community);
    }
    virtual ~SNMPTrap(){
        this->releasePoolState();                 /* shared teardown path      */
        if(_trapOIDOwned) asn_delete(trapOID);
        trapOID = nullptr;
        _trapOIDOwned = false;
    }
    
    IPAddress agentIP;
    OIDType* trapOID = nullptr;

    /* v3.3.4: trap sysUpTime resolution — defined in SNMPTrap.cpp (needs the
     * complete SNMPAgent type). Order: sketch callback first (unchanged
     * pre-3.3.4 behaviour), else the library built-in uptime, else nullptr
     * (opt-out builds) which callers treat as 0 exactly as before. */
    TimestampCallback* effectiveUptimeCallback();
    TimestampCallback* uptimeCallback = nullptr;
    short genericTrap = 6;
    short specificTrap = 1;
    
    short trapUDPport = 162;
    
    bool inform = false;

    bool setInform(bool inf){
        this->inform = inf;
        ASN_TYPE pduType = this->packetPDUType;
        switch(this->snmpVersion){
            case SNMP_VERSION_1:
                pduType = TrapPDU;
            break;
            case SNMP_VERSION_2C:
                pduType = this->inform ? InformRequestPDU : Trapv2PDU;
            break;
            default:
            break;
        }
        this->setPDUType(pduType);
        return true;
    }
    
    void setTrapOID(OIDType* oid){
        if(_trapOIDOwned) asn_delete(trapOID);
        trapOID = oid;
        _trapOIDOwned = false;
    }

    /* v3.3.3: owning setters heap-allocate the trap OID.  A persistent trap
     * object must hold NO pool-backed state between sends (ASNPool::resetAll()
     * in loop() flag-frees all transient slots every tick; a pool-resident
     * trapOID would be stale by construction).  asn_delete() dispatches heap
     * pointers correctly (isInPool() false -> operator delete), so ownership
     * semantics are unchanged. */
    void setTrapOID(const char* oid_str){
        if(_trapOIDOwned) asn_delete(trapOID);
        trapOID = new OIDType(oid_str);
        _trapOIDOwned = true;
    }

    void setTrapOID(const OIDType& oid_ref){
        if(_trapOIDOwned) asn_delete(trapOID);
        trapOID = new OIDType(oid_ref);
        _trapOIDOwned = true;
    }
    
    void setSpecificTrap(short num){
        specificTrap = num;
    }

    void setIP(IPAddress ip){
        agentIP = ip;
    }
    
    void setUDPport(short port){
        trapUDPport = port;
    }
    
    void setUDP(UDP* udp){
        _udp = udp;
    }
    
    void stop(){
        _udp = nullptr;
    }
    
    void setUptimeCallback(TimestampCallback* uptime){
        uptimeCallback = uptime;
    }
    
    bool addOIDPointer(ValueCallback* callback);
    
    UDP* _udp = nullptr;    /* newRequestID=false rebuilds the tree while preserving the stored
     * requestID — used by the stateless inform-retry path (sendTo with
     * skipBuild=true), which must re-emit the ORIGINAL ID. */
    bool buildForSending(bool newRequestID = true){
        if(newRequestID) this->setRequestID(SNMPPacket::generate_request_id());

        if(this->snmpVersion == SNMP_VERSION_1){
            return this->build();
        } else {
            return SNMPPacket::build();
        }
    }

    /* v3.3.3 stateless send: builds a fresh tree EVERY call (no tree survives
     * between sends), serialises, transmits, then releases all pool state.
     * skipBuild no longer means "reuse the previous tree" (there is none) —
     * it means "do not regenerate the requestID" (inform retries). */
    bool sendTo(const IPAddress& ip, bool skipBuild = false){
        ASNPool::resetAll();

        if(!skipBuild) {
            this->setRequestID(SNMPPacket::generate_request_id());
        }
        bool buildStatus = this->buildForSending(false);

        if(!_udp){
            this->releasePoolState();
            return false;
        }

        if(!this->packet){
            this->releasePoolState();
            return false;
        }

        if(!buildStatus){
            SNMP_LOGW("Failed Building packet..");
            this->releasePoolState();
            return false;
        }

        uint8_t _packetBuffer[MAX_SNMP_PACKET_LENGTH] = {0};
        int length = packet->serialise(_packetBuffer, MAX_SNMP_PACKET_LENGTH);

        /* Once the bytes are on the wire (or the serialise failed), nothing
         * pool-backed in this object may outlive this call.  The serialized
         * form is in _packetBuffer; pool slots are all freed HERE while they
         * are still in the sanctioned resetAll()-freed state. */
        bool sent = false;
        if(length > 0){
            _udp->beginPacket(ip, trapUDPport);
            _udp->write(_packetBuffer, length);
            sent = ( _udp->endPacket() != 0 );
        }
        this->releasePoolState();
        return sent;
    }

  protected:
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_TRAP] = {nullptr};
    int callbacksCount = 0;
    bool _trapOIDOwned = false;

    ComplexType* generateVarBindListRaw() override;

    static OIDType s_timestampOID;
    static OIDType s_snmpTrapOID;
    OIDType* timestampOID = &s_timestampOID;
    OIDType* snmpTrapOID  = &s_snmpTrapOID;

    bool build() override;
};
#endif /* !SNMP_NO_TRAPS */

#endif
