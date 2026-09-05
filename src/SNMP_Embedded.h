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

/* v3.3.4: record of what addRFC1213SystemGroup() actually registered.
 * sysUpTime is nullptr here when the built-in dynamic uptime is active
 * (default build) — it has no user handle by design. */
struct RFC1213Config {
    ValueCallback* sysDescr        = nullptr;
    ValueCallback* sysUpTime       = nullptr;   /* only set when the sketch owns uptime (SNMP_NO_BUILTIN_SYSUPTIME build, self-registered) */
    ValueCallback* sysContact      = nullptr;
    ValueCallback* sysName         = nullptr;
    ValueCallback* sysLocation     = nullptr;
    ValueCallback* sysServices     = nullptr;
    uint8_t        registeredCount = 0;         /* handlers this call actually added */
};

class SNMPAgent {
    public:
        SNMPAgent(){
#if SNMP_POOL_LOCK_AT_BOOT
            ASNPool::lockInArena();   /* v3.3.0: claim the arena at global-ctor time (pristine heap) */
#endif
            registerBuiltinUptime();
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
            registerBuiltinUptime();
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
            _readOnlyCommunity[len] = 0;
            registerBuiltinUptime();
            if(SNMPAgent::agentsCount < SNMP_MAX_AGENTS){
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

        /* ---- v3.3.4: RFC1213 system group ---------------------------------
         * One-call registration of any subset of the six configurable system
         * OIDs. Pass only what you want (defaults are "not configured"); each
         * registered OID costs exactly one pool slot + its buffer. RW strings
         * REQUIRE len > 0 (sizeof of the buffer) — a zero length is a loud
         * configuration error and the OID is not registered.
         *
         * sysObjectID is deliberately not covered: it is YOUR enterprise OID —
         * add manually if wanted: snmp.addOIDHandler(RFC1213_OID_sysObjectID, "1.3.6.1.4.1.99999");
         *
         * sysUpTime: registered automatically by the library as a live value
         * computed at request time (never stale, zero sketch code, and trap
         * timestamps follow the same source). Define SNMP_NO_BUILTIN_SYSUPTIME
         * to remove it and manage uptime yourself.
         * -------------------------------------------------------------------- */
        RFC1213Config addRFC1213SystemGroup(
            const char* sysDescr     = nullptr,               /* RO static string (e.g. "My ESP8266 sensor v1") */
            char**      sysContact   = nullptr, size_t contactLen   = 0,  /* RW; pass &ptr, sizeof(buf) */
            char**      sysName      = nullptr, size_t nameLen      = 0,  /* RW */
            char**      sysLocation  = nullptr, size_t locationLen = 0,  /* RW */
            int*         sysServices  = nullptr);                      /* RO; typical 72 (IP+TCP host), 64 (L3), 0 (endpoint) */

        /* ---- v3.3.5: auto-sizing overloads — pass the ARRAY, not &ptr+sizeof ----
         * The library deduces each RW buffer's capacity from the array type, so
         * the five-input call has zero sizeof() trivia:
         *   snmp.addRFC1213SystemGroup(descr, sysContactBuf, sysNameBuf, sysLocBuf, &sysServices);
         * Skip an OID with RFC1213_SKIP in its slot:
         *   snmp.addRFC1213SystemGroup(descr, RFC1213_SKIP, sysNameBuf, RFC1213_SKIP, &sysServices);
         * The buffer must be a real char array (char buf[64]) — a bare char* has no
         * deducible capacity and fails to compile rather than guessing. For heap or
         * runtime-sized storage, use the (char**, size_t) pointer form above.
         * sysDescr stays read-only: no length needed, the library never writes it. */
        struct Skip_t { Skip_t() = default; };            /* sentinel type; use RFC1213_SKIP */

        /* A read-write string buffer the library can size by itself. Constructed
         * from a real char array (char buf[64]) or from RFC1213_SKIP (= "not
         * configured"); NOT constructible from a bare char* (capacity unknown
         * -> compile error). Zero allocation: it only carries (char* data, len)
         * to a dedicated array-backed callback. */
        struct SysBuf {
            char*    data;
            size_t   len;
            SysBuf() = delete;                          /* no accidental empty */
            SysBuf(Skip_t) : data(nullptr), len(0) {}   /* RFC1213_SKIP -> skip this OID */
            template <size_t N>
            SysBuf(char* (&buf)[N]) : data(buf), len(N) {}  /* char* name[64] */
            template <size_t N>
            SysBuf(char (&buf)[N])  : data(buf), len(N) {}  /* char name[64] (direct array) */
        };

        /* AUTO-SIZE form: real arrays for the three RW strings — five inputs, no sizeof(). */
        RFC1213Config addRFC1213SystemGroup(
            const char*         sysDescr,
            SysBuf              sysContact,
            SysBuf              sysName,
            SysBuf              sysLocation,
            int*                sysServices)
        {
            return addRFC1213SystemGroupRaw(sysDescr,
                                         sysContact.data, sysContact.len,
                                         sysName.data,    sysName.len,
                                         sysLocation.data,sysLocation.len,
                                         sysServices);
        }

        /* Internal: array-backed RW string registration (SysBuf core). */
        RFC1213Config addRFC1213SystemGroupRaw(
            const char* sysDescr,
            char*       sysContact,    size_t contactLen,
            char*       sysName,       size_t nameLen,
            char*       sysLocation,   size_t locationLen,
            int*        sysServices);

        /* Override the uptime clock source (ms). Default: millis(). Mostly for
         * tests (fake clock); usable for custom tick sources on hardware. */
        static void setUptimeSource(unsigned long (*source)());
        /* Current uptime in TimeTicks centiseconds, computed at call time. */
        static unsigned long uptimeCs();

        /* ---- v3.3.4: RFC1213 system group (implementation notes) -------------
         * addRFC1213SystemGroup() is a conditional dispatch over the EXISTING
         * addXxxHandler() calls — no new registration machinery, no new pool
         * interaction, and derived sizing counts its registrations like any
         * other handler. Rules enforced loudly (never silently):
         *   - RW strings REQUIRE len > 0; len==0 is a configuration error, the
         *     OID is NOT registered.
         *   - A zero-OID call (all defaults) registers nothing: "none" is a
         *     valid posture (use platformio_minimal-style stripped builds).
         *   - The helper must be the only registrar for its six OIDs; manual
         *     duplicates collide through the normal duplicate-OID path.
         * sysObjectID is deliberately absent — it is the user's enterprise OID.
         * ---------------------------------------------------------------------- */

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

#ifdef COMPILING_TESTS
        /* Host-suite access to the internal registration table (read-only).
         * Lets tests assert exactly what the constructor/helper registered
         * without reaching into private state. Not compiled in sketches. */
        ValueCallback* const* testCallbacks() const { return callbacks; }
        int testCallbacksCount() const { return callbacksCount; }
        /* Pop this agent from the global registry so later test cases can
         * construct agents (agents[] has SNMP_MAX_AGENTS slots). */
        void testReleaseFromRegistry(){
            for(int i = 0; i < agentsCount; i++){
                if(agents[i] == this){
                    for(int j = i; j < agentsCount - 1; j++)
                        agents[j] = agents[j+1];
                    agents[--agentsCount] = nullptr;
                    return;
                }
            }
        }
        static int testAgentsCount(){ return agentsCount; }
#endif

        snmp_request_id_t sendTrapTo(SNMPTrap* trap, const IPAddress& ip, bool replaceQueuedRequests = true, int retries = 0, int delay_ms = 30000);
        static void markTrapDeleted(SNMPTrap* trap);

    private:
        ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
        int callbacksCount = 0;
        ValueCallback* addHandler(ValueCallback *callback, bool isSettable);

        /* v3.3.4: handle of the built-in sysUpTime registration (nullptr in
         * opt-out builds). Used to refuse duplicate sysUpTime registrations
         * loudly instead of leaving dead handlers in the table. */
        ValueCallback* _builtinUptimeCb = nullptr;

        /* v3.3.4: register the library-owned dynamic sysUpTime (1 pool slot) —
         * skipped entirely under SNMP_NO_BUILTIN_SYSUPTIME. Must run before
         * any sketch registration so sorting/duplicate logic sees it first. */
        void registerBuiltinUptime();

        static uint32_t _snmp_builtin_uptime_var;   /* trap-timestamp mirror, refreshed in loop() */

        /* SNMPTrap resolves its timestamp source to the built-in mirror. */
        friend class SNMPTrap;

        static void informCallback(void*, snmp_request_id_t, bool);
        void handleInformQueue();

        UDP* _udp[SNMP_MAX_UDP_PER_AGENT] = {nullptr};
        int udpCount = 0;

        char oidPrefix[SNMP_MAX_OID_STR_LEN + 1] = {0};
        uint8_t _packetBuffer[MAX_SNMP_PACKET_LENGTH] = {0};

        SortableOIDType* buildOIDWithPrefix(const char *oid, bool overwritePrefix);

        static SNMPAgent* agents[SNMP_MAX_AGENTS];
        static int agentsCount;
    public:
        /* v3.3.4: mirror of the built-in uptime, kept fresh at the top of
         * loop() so SNMPTrap's timestamp varbind (RFC 1215/3418 convention:
         * first varbind = sysUpTime) is always current without sketch code.
         * Sketched-owned uptime (flag builds / explicit setUptimeCallback)
         * behaves exactly as before. */
        static uint32_t builtinUptimeCs();

        struct InformItem* informList[SNMP_MAX_TRAPS_INFLIGHT] = {nullptr};
        int informCount = 0;
};

/* v3.3.5: sentinel for addRFC1213SystemGroup()'s auto-size form — "skip this
 * OID". Declared after the class (the type is SNMPAgent::Skip_t); C++11 keeps
 * the aggregate initialization a compile-time constant, so it works in any
 * call site, including sketches. */
static const SNMPAgent::Skip_t RFC1213_SKIP = SNMPAgent::Skip_t();

#endif
