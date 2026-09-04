#ifndef SNMPAgent_h
#define SNMPAgent_h

#ifdef COMPILING_TESTS
	#include "tests/required/millis.h"
	#include "tests/required/IPAddress.h"
	#include "tests/required/UDP.h"
	#include "tests/required/Print.h"
#else
	#include <Arduino.h>
	#include "IPAddress.h"
	
	#if defined(ESP8266) || defined(ESP32)
		#include <WiFiUdp.h>
	#else
		#include "Udp.h"
	#endif
#endif

#include "include/BER.h"
#include "include/VarBinds.h"
#include "include/SNMPPacket.h"
#include "SNMPTrap.h"
#include "include/SNMPResponse.h"
#include "include/ValueCallbacks.h"
#include "include/SNMPParser.h"
#include "include/defs.h"
#include "include/SNMPInform.h"

class SNMPAgent {
    public:
        SNMPAgent(){
#if SNMP_POOL_LOCK_AT_BOOT
            ASNPool::lockInArena();   /* v3.3.0: claim the arena at global-ctor time (pristine heap) */
#endif
            if(SNMPAgent::agentsCount < SNMP_MAX_AGENTS){
                SNMPAgent::agents[SNMPAgent::agentsCount++] = this;
            }
        }

        SNMPAgent(const char* community){
#if SNMP_POOL_LOCK_AT_BOOT
            ASNPool::lockInArena();   /* v3.3.0: claim the arena at global-ctor time (pristine heap) */
#endif
            size_t len = strlen(community);
            if(len > SNMP_MAX_COMMUNITY_LEN) len = SNMP_MAX_COMMUNITY_LEN;
            memcpy(_community, community, len);
            _community[len] = 0;
            if(SNMPAgent::agentsCount < SNMP_MAX_AGENTS){
                SNMPAgent::agents[SNMPAgent::agentsCount++] = this;
            }
        }

        SNMPAgent(const char* readOnlyCommunity, const char* readWriteCommunity){
#if SNMP_POOL_LOCK_AT_BOOT
            ASNPool::lockInArena();   /* v3.3.0: claim the arena at global-ctor time (pristine heap) */
#endif
            size_t len = strlen(readWriteCommunity);
            if(len > SNMP_MAX_COMMUNITY_LEN) len = SNMP_MAX_COMMUNITY_LEN;
            memcpy(_community, readWriteCommunity, len);
            _community[len] = 0;
            len = strlen(readOnlyCommunity);
            if(len > SNMP_MAX_COMMUNITY_LEN) len = SNMP_MAX_COMMUNITY_LEN;
            memcpy(_readOnlyCommunity, readOnlyCommunity, len);
            _readOnlyCommunity[len] = 0;            if(SNMPAgent::agentsCount < SNMP_MAX_AGENTS){
                SNMPAgent::agents[SNMPAgent::agentsCount++] = this;
            }
        }

        /* Runtime library version (LIBRARY_VERSION from defs.h). Use in sketches to
           print/serve the exact build under test, e.g. hardware-test banners. */
        static const char* getVersion(){ return LIBRARY_VERSION; }

        void
        setReadOnlyCommunity(const char* community){
            size_t len = strlen(community);
            if(len > SNMP_MAX_COMMUNITY_LEN) len = SNMP_MAX_COMMUNITY_LEN;
            memcpy(this->_readOnlyCommunity, community, len);
            this->_readOnlyCommunity[len] = 0;
        }

        void setReadWriteCommunity(const char* community){
            size_t len = strlen(community);
            if(len > SNMP_MAX_COMMUNITY_LEN) len = SNMP_MAX_COMMUNITY_LEN;
            memcpy(this->_community, community, len);
            this->_community[len] = 0;
        }

        char _community[SNMP_MAX_COMMUNITY_LEN + 1] = "public";
        char _readOnlyCommunity[SNMP_MAX_COMMUNITY_LEN + 1] = {0};

        ValueCallback* addIntegerHandler(const char *oid, int* value, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addReadOnlyIntegerHandler(const char *oid, int value, bool overwritePrefix = false);
        ValueCallback* addDynamicIntegerHandler(const char *oid, GETINT_FUNC callback_func, bool overwritePrefix = false);
        ValueCallback* addReadWriteStringHandler(const char *oid, char** value, size_t max_len = 0, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addReadOnlyStaticStringHandler(const char *oid, const char* value, bool overwritePrefix = false);
        ValueCallback* addDynamicReadOnlyStringHandler(const char *oid, GETSTRING_FUNC callback_func, bool overwritePrefix = false);
        ValueCallback* addOpaqueHandler(const char *oid, uint8_t* value, size_t data_len, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addTimestampHandler(const char *oid, uint32_t* value, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addDynamicReadOnlyTimestampHandler(const char *oid, GETUINT_FUNC callback_func, bool overwritePrefix = false);
        ValueCallback* addOIDHandler(const char *oid, const char* value, bool overwritePrefix = false);
        ValueCallback* addCounter64Handler(const char *oid, uint64_t* value, bool overwritePrefix = false);
        ValueCallback* addCounter32Handler(const char *oid, uint32_t* value, bool overwritePrefix = false);
        ValueCallback* addGaugeHandler(const char *oid, uint32_t* value, bool overwritePrefix = false);
        // Depreciated, use addGaugeHandler()
        __attribute__((deprecated)) ValueCallback* addGuageHandler(const char *oid, uint32_t* value, bool overwritePrefix = false) {
            return addGaugeHandler(oid, value, overwritePrefix);
        }

        void
        setUDP(UDP* udp);
        bool restartUDP();

        void
        begin();
        void
        begin(const char* oidPrefix);
        void stop();
	    enum SNMP_ERROR_RESPONSE loop();

        short AgentUDPport = 161;
        void setUDPport(short port){
	        AgentUDPport = port;
        }

        bool setOccurred = false;
        void resetSetOccurred(){
            setOccurred = false;
        }

        bool removeHandler(ValueCallback* callback);
        bool sortHandlers();

        void printAllOIDsTo(Print& out) const;

        snmp_request_id_t sendTrapTo(SNMPTrap* trap, const IPAddress& ip, bool replaceQueuedRequests = true, int retries = 0, int delay_ms = 30000);
        static void markTrapDeleted(SNMPTrap* trap);

    private:
        ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
        int callbacksCount = 0;
        ValueCallback* addHandler(ValueCallback *callback, bool isSettable);

        static void informCallback(void*, snmp_request_id_t, bool);
        void handleInformQueue();

        UDP* _udp[SNMP_MAX_UDP_PER_AGENT] = {nullptr};
        int udpCount = 0;

        char oidPrefix[SNMP_MAX_OID_STR_LEN + 1] = {0};
        uint8_t _packetBuffer[MAX_SNMP_PACKET_LENGTH] = {0};

        SortableOIDType* buildOIDWithPrefix(const char *oid, bool overwritePrefix);

        static SNMPAgent* agents[SNMP_MAX_AGENTS];
        static int agentsCount;

        struct InformItem* informList[SNMP_MAX_TRAPS_INFLIGHT] = {nullptr};
        int informCount = 0;
};

#endif
