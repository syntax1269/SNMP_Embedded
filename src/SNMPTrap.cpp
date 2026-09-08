#if !SNMP_NO_TRAPS
#include "SNMPTrap.h"
#include "SNMP_Embedded.h"   /* v3.3.4: complete SNMPAgent for the built-in uptime mirror */
#include "include/SNMPParser.h"
#include "include/defs.h"

/* v3.4.2: the shared_ptr generateVarBindList() override was removed with the
 * virtual itself (zero callers; each construction cost a heap control block
 * — Report_001 finding #1).  Trap building goes through generateVarBindListRaw(). */

/* v3.3.4: trap sysUpTime resolution order —
 *   1. sketch-supplied callback (unchanged pre-3.3.4 behaviour)
 *   2. the library built-in uptime (default build): a static TimestampCallback
 *      over SNMPAgent::_snmp_builtin_uptime_var, which loop() refreshes each
 *      tick (request-time computation covers traps sent before the first
 *      tick). GET uptime and trap timestamp can never disagree.
 *   3. opt-out builds (SNMP_NO_BUILTIN_SYSUPTIME) with no sketch callback:
 *      nullptr -> callers fall back to 0 exactly as pre-3.3.4. */
TimestampCallback* SNMPTrap::effectiveUptimeCallback(){
    if(uptimeCallback) return uptimeCallback;
#if SNMP_HAS_BUILTIN_SYSUPTIME
    /* function-local statics: no init-order hazard; never own pool state.
     * The callback carries a REAL OID — ValueCallback::getValueForCallback
     * unconditionally logs OID->string(), so a null OID here would crash every
     * built-in-uptime trap send (found on hardware, Sept 2026).
     * Heap-allocated leaky singletons: the callback destructor asn_delete()s its
     * OID at static teardown, and a stack/static OID would be freed twice (once
     * via asn_delete, once by its own destructor) -> abort at exit. Leak-by-design
     * matches the pool's permanent-allocation doctrine for agent-lifetime objects. */
    static SortableOIDType* s_builtinTsOID = new SortableOIDType(RFC1213_OID_sysUpTime);
    static TimestampCallback* builtinTs = new TimestampCallback(s_builtinTsOID, &SNMPAgent::_snmp_builtin_uptime_var);
    return builtinTs;
#else
    return nullptr;
#endif
}

OIDType SNMPTrap::s_timestampOID(RFC1213_OID_sysUpTime);
OIDType SNMPTrap::s_snmpTrapOID(SNMPv2_SNMPTRAP_OID_0);

/* v3.3.3: destructor inlined in SNMPTrap.h (delegates to the shared
 * releasePoolState() teardown path). */

static bool _trap_build_fill_pdu(ComplexType* trapPDU, void* userdata){
    SNMPTrap* self = static_cast<SNMPTrap*>(userdata);
    trapPDU->addValueToListRaw(self->trapOID->cloneRaw());
    trapPDU->addValueToListRaw(asn_new<NetworkAddress>(self->agentIP));
    trapPDU->addValueToListRaw(asn_new<IntegerType>(self->genericTrap));
    trapPDU->addValueToListRaw(asn_new<IntegerType>(self->specificTrap));

    /* v3.3.4: sketch callback wins; else the library built-in uptime supplies
     * a live value (see SNMPTrap::effectiveUptimeCallback). */
    if(TimestampCallback* up = self->effectiveUptimeCallback()){
        AsnPtr<BER_CONTAINER> ts = ValueCallback::getValueForCallback(up);
        if(ts) trapPDU->addValueToListRaw(asn_new<TimestampType>(static_cast<TimestampType*>(ts.get())->_value));
        else   trapPDU->addValueToListRaw(asn_new<TimestampType>(0));
    } else {
        trapPDU->addValueToListRaw(asn_new<TimestampType>(0));
    }
    return true;
}

bool SNMPTrap::build(){
    if(!this->trapOID) return false;

    this->packetPDUType = TrapPDU;

    return _build_pdu_envelope(_trap_build_fill_pdu, this);
}

ComplexType* SNMPTrap::generateVarBindListRaw(){
    SNMP_LOGD("generateVarBindListRaw from SNMPTrap");
    ComplexType* ourVBList = asn_new<ComplexType>(STRUCTURE);
    if(!ourVBList){
        SNMP_LOGE("SNMPTrap::generateVarBindListRaw: pool exhausted (ourVBList). Raise SNMP_POOL_ASN_OBJECTS.\n");
        return nullptr;
    }
    ourVBList->_ownsChildren = true;

    if(this->snmpVersion == SNMP_VERSION_2C){
        if(!this->trapOID){
            asn_delete(ourVBList);
            return nullptr;
        }
        ComplexType* timestampVarBind = asn_new<ComplexType>(STRUCTURE);
        if(!timestampVarBind){
            SNMP_LOGE("SNMPTrap::generateVarBindListRaw: pool exhausted (timestampVarBind).\n");
            asn_delete(ourVBList);
            return nullptr;
        }
        timestampVarBind->_ownsChildren = true;
        timestampVarBind->addValueToListRaw(timestampOID->cloneRaw());

        /* v3.3.4: same resolution order as the v1 trap path — sketch callback,
         * else the library built-in uptime. */
        if(TimestampCallback* up = effectiveUptimeCallback()){
            AsnPtr<BER_CONTAINER> ts = ValueCallback::getValueForCallback(up);
            if(ts) timestampVarBind->addValueToListRaw(asn_new<TimestampType>(static_cast<TimestampType*>(ts.get())->_value));
            else   timestampVarBind->addValueToListRaw(asn_new<TimestampType>(0));
        } else {
            timestampVarBind->addValueToListRaw(asn_new<TimestampType>(0));
        }
        ourVBList->addValueToListRaw(timestampVarBind);

        ComplexType* oidVarBind = asn_new<ComplexType>(STRUCTURE);
        if(!oidVarBind){
            SNMP_LOGE("SNMPTrap::generateVarBindListRaw: pool exhausted (oidVarBind).\n");
            asn_delete(ourVBList);
            return nullptr;
        }
        oidVarBind->_ownsChildren = true;
        oidVarBind->addValueToListRaw(snmpTrapOID->cloneRaw());
        oidVarBind->addValueToListRaw(trapOID->cloneRaw());
        ourVBList->addValueToListRaw(oidVarBind);
    }

    for(int i = 0; i < callbacksCount; i++){
        ValueCallback* value = callbacks[i];
        if(!value) continue;
        ComplexType* varBind = asn_new<ComplexType>(STRUCTURE);
        if(!varBind){
            SNMP_LOGE("SNMPTrap::generateVarBindListRaw: pool exhausted (callback %d/%d).\n", i, callbacksCount);
            asn_delete(ourVBList);
            return nullptr;
        }
        varBind->_ownsChildren = true;

        varBind->addValueToListRaw(value->OID->cloneRaw());

        AsnPtr<BER_CONTAINER> valueSP = ValueCallback::getValueForCallback(value);
        BER_CONTAINER* src = valueSP.get();
        BER_CONTAINER* clonedValue = nullptr;
        if(!src){
            clonedValue = asn_new<NullType>();
        } else switch(src->_type){
            case INTEGER:        clonedValue = asn_new<IntegerType>(static_cast<IntegerType*>(src)->_value); break;
            case STRING:
            {
                OctetType* so = static_cast<OctetType*>(src);
                clonedValue = asn_new<OctetType>(so->_value, so->_valueLen);
            } break;
            case OID:            clonedValue = static_cast<OIDType*>(src)->cloneRaw(); break;
            case NULLTYPE:       clonedValue = asn_new<NullType>(); break;
            case NOSUCHOBJECT:   clonedValue = asn_new<ImplicitNullType>(NOSUCHOBJECT); break;
            case NOSUCHINSTANCE: clonedValue = asn_new<ImplicitNullType>(NOSUCHINSTANCE); break;
            case ENDOFMIBVIEW:   clonedValue = asn_new<ImplicitNullType>(ENDOFMIBVIEW); break;
            case NETWORK_ADDRESS:
            {
                NetworkAddress* so = static_cast<NetworkAddress*>(src);
                clonedValue = asn_new<NetworkAddress>(so->_value);
            } break;
            case TIMESTAMP:      clonedValue = asn_new<TimestampType>(static_cast<TimestampType*>(src)->_value); break;
            case COUNTER32:      clonedValue = asn_new<Counter32>(static_cast<Counter32*>(src)->_value); break;
            case GAUGE32:        clonedValue = asn_new<Gauge>(static_cast<Gauge*>(src)->_value); break;
            case COUNTER64:      clonedValue = asn_new<Counter64>(static_cast<Counter64*>(src)->_value); break;
            case OPAQUE:
            {
                OpaqueType* so = static_cast<OpaqueType*>(src);
                clonedValue = asn_new<OpaqueType>(so->_value, so->_dataLength);
            } break;
            default:
                clonedValue = asn_new<NullType>(); break;
        }
        varBind->addValueToListRaw(clonedValue);

        ourVBList->addValueToListRaw(varBind);
    }

    return ourVBList;
}

bool SNMPTrap::addOIDPointer(ValueCallback* callback){
    if(!callback) return false;
    if(callbacksCount >= SNMP_MAX_CALLBACKS_PER_TRAP){
        SNMP_LOGE("SNMPTrap::addOIDPointer: callbacks[] full (%d slots). Raise SNMP_MAX_CALLBACKS_PER_TRAP.\n",
                  SNMP_MAX_CALLBACKS_PER_TRAP);
        return false;
    }
    callbacks[callbacksCount++] = callback;
    return true;
}
#endif /* !SNMP_NO_TRAPS */
