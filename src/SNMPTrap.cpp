#include "SNMPTrap.h"
#include "include/SNMPParser.h"
#include "include/defs.h"

/* Pool object deleter helper — must match the deleter used in SNMPPacket.cpp.
 * asn_delete() correctly returns a pool-allocated BER_CONTAINER slot back to
 * the ASNPool free-list instead of calling operator delete (which would UB
 * on a placement-new'd slot in the static pool, corrupting the pool metadata
 * and silently dropping all responses on ESP8266). */
namespace {
    struct trap_pool_deleter {
        template <typename T>
        void operator()(T* p) const noexcept {
            asn_delete(static_cast<BER_CONTAINER*>(p));
        }
    };
}

std::shared_ptr<ComplexType> SNMPTrap::generateVarBindList(){
    return std::shared_ptr<ComplexType>(generateVarBindListRaw(), trap_pool_deleter());
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

    if(self->uptimeCallback){
        auto sp = std::static_pointer_cast<TimestampType>(ValueCallback::getValueForCallback(self->uptimeCallback));
        if(sp) trapPDU->addValueToListRaw(asn_new<TimestampType>(sp->_value));
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

        if(uptimeCallback){
            auto sp = std::static_pointer_cast<TimestampType>(ValueCallback::getValueForCallback(uptimeCallback));
            if(sp) timestampVarBind->addValueToListRaw(asn_new<TimestampType>(sp->_value));
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

        auto valueSP = ValueCallback::getValueForCallback(value);
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
