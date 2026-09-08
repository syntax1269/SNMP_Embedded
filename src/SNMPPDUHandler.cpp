#include "include/defs.h"
#include "include/SNMPParser.h"
#include "include/BER.h"
#include "include/ValueCallbacks.h"

/* Every `asn_new<T>()` returns a RAW POINTER into the static ASNPool
 * (placement-new slots).  When such a raw pointer is bound to a function
 * parameter of type `const std::shared_ptr<BER_CONTAINER>&`, C++
 * implicitly constructs a TEMPORARY shared_ptr using the DEFAULT
 * `delete T` deleter — which immediately calls `delete` on a pool slot
 * address at scope exit → Undefined Behavior.  On ESP8266 this corrupted
 * pool metadata silently (no exception triggered since the double-free
 * happened on a slot not currently in the free-list), causing
 * SNMPResponse encode path to fail to build even a single VarBind →
 * ZERO UDP TX bytes sent, agent DEAF despite UDP RX confirmed.
 *
 * FIX: wrap every `asn_new<T>()` passed into a `shared_ptr<T>` context
 * with `pool_asn_sp(...)` below.  It constructs a shared_ptr whose
 * custom deleter calls `asn_delete` instead of `operator delete`. */
/* v3.4.2: pool-owning AsnPtr replaces the shared_ptr wrapper — no control
 * block, destruction still through asn_delete. */
template <typename T>
static inline AsnPtr<BER_CONTAINER> pool_asn_sp(T* raw_pool_ptr) noexcept {
    static_assert(std::is_base_of<BER_CONTAINER, T>::value,
                  "pool_asn_sp only accepts BER_CONTAINER-derived pointers");
    return AsnPtr<BER_CONTAINER>(static_cast<BER_CONTAINER*>(raw_pool_ptr));
}

template<typename... Args>
static inline bool appendResponseVarBind(VarBind out[], int &outCount, Args&&... args){
    if(outCount >= SNMP_MAX_VARBINDS){
        /* Overflow is LOUD: fail the response rather than silently drop. */
        SNMP_LOGW("Response varbind #%d exceeds SNMP_MAX_VARBINDS (%d): dropped. Raise SNMP_MAX_VARBINDS via sketch #define before #include <SNMP_Embedded.h>.\n",
                  outCount + 1, SNMP_MAX_VARBINDS);
        return false;
    }
    out[outCount].~VarBind();
    new (&out[outCount]) VarBind(std::forward<Args>(args)...);
    outCount++;
    return true;
}

bool handleGetRequestPDU(ValueCallback* const *callbacks, int callbacksCount, const VarBind* varbindList, int varbindCount, VarBind outResponseList[], int &outResponseCount, SNMP_VERSION snmpVersion, bool isGetNextRequest){
    SNMP_LOGD("handleGetRequestPDU\n");
    for(int vbIdx = 0; vbIdx < varbindCount; vbIdx++){
        const VarBind& requestVarBind = varbindList[vbIdx];
        SNMP_LOGD("finding callback for OID: %s\n", requestVarBind.oid->string());
        ValueCallback* callback = ValueCallback::findCallback(callbacks, callbacksCount, requestVarBind.oid, isGetNextRequest);
        if(!callback){
            SNMP_LOGD("Couldn't find callback\n");
#if 1
            if(isGetNextRequest){
                if(!appendResponseVarBind(outResponseList, outResponseCount, requestVarBind, pool_asn_sp(asn_new<ImplicitNullType>(ENDOFMIBVIEW)))) continue;
            } else {
                if(!appendResponseVarBind(outResponseList, outResponseCount, requestVarBind, pool_asn_sp(asn_new<ImplicitNullType>(NOSUCHOBJECT)))) continue;
            }

#else
            if(!appendResponseVarBind(outResponseList, outResponseCount, generateErrorResponse(SNMP_ERROR_VERSION_CTRL_DEF(NOT_WRITABLE, snmpVersion, NO_SUCH_NAME), requestVarBind.oid))) continue;
#endif
            continue;
        }

        SNMP_LOGD("Callback found with OID: %s\n", callback->OID->string());
        AsnPtr<BER_CONTAINER> value = ValueCallback::getValueForCallback(callback);

        if(!value){
            SNMP_LOGD("Couldn't get value for callback\n");
            if(!appendResponseVarBind(outResponseList, outResponseCount, callback->OID, SNMP_ERROR_VERSION_CTRL(GEN_ERR, snmpVersion))) continue;
            continue;
        }

        if(!appendResponseVarBind(outResponseList, outResponseCount, callback->OID, std::move(value))) continue;
    }
    return true;
}

bool handleSetRequestPDU(ValueCallback* const *callbacks, int callbacksCount, const VarBind* varbindList, int varbindCount, VarBind outResponseList[], int &outResponseCount, SNMP_VERSION snmpVersion){
    SNMP_LOGD("handleSetRequestPDU\n");
    for(int vbIdx = 0; vbIdx < varbindCount; vbIdx++){
        const VarBind& requestVarBind = varbindList[vbIdx];
        SNMP_LOGD("finding callback for OID: %s\n", requestVarBind.oid->string());
        ValueCallback* callback = ValueCallback::findCallback(callbacks, callbacksCount, requestVarBind.oid, false);
        if(!callback){
            SNMP_LOGD("Couldn't find callback\n");
            if(!appendResponseVarBind(outResponseList, outResponseCount, requestVarBind.oid->cloneRaw(), SNMP_ERROR_VERSION_CTRL_DEF(NOT_WRITABLE, snmpVersion, NO_SUCH_NAME))) continue;
            continue;
        }

        SNMP_LOGD("Callback found with OID: %s\n", callback->OID->string());

        if(callback->type != requestVarBind.type){
            SNMP_LOGD("Callback Type mismatch: %d\n", callback->type);
            if(!appendResponseVarBind(outResponseList, outResponseCount, requestVarBind.oid->cloneRaw(), SNMP_ERROR_VERSION_CTRL_DEF(WRONG_TYPE, snmpVersion, BAD_VALUE))) continue;
            continue;
        }

        if(!callback->isSettable){
            SNMP_LOGD("Cannot set this object\n");
            if(!appendResponseVarBind(outResponseList, outResponseCount, requestVarBind.oid->cloneRaw(), SNMP_ERROR_VERSION_CTRL(READ_ONLY, snmpVersion))) continue;
            continue;
        }
        /* v3.4.2: borrowed const view — setValueForCallback reads the value
         * during the call and never retains it. */
        SNMP_ERROR_STATUS setError = ValueCallback::setValueForCallback(callback, requestVarBind.value);
        if(setError != NO_ERROR){
            SNMP_LOGD("Attempting to set Variable failed: %d\n", setError);
            if(!appendResponseVarBind(outResponseList, outResponseCount, callback->OID, SNMP_ERROR_VERSION_CTRL(setError, snmpVersion))) continue;
            continue;
        }

        AsnPtr<BER_CONTAINER> value = ValueCallback::getValueForCallback(callback);

        if(!value){
            SNMP_LOGD("Couldn't get value for callback\n");
            if(!appendResponseVarBind(outResponseList, outResponseCount, callback->OID, SNMP_ERROR_VERSION_CTRL(GEN_ERR, snmpVersion))) continue;
            continue;
        }

        if(!appendResponseVarBind(outResponseList, outResponseCount, callback->OID, std::move(value))) continue;
    }
    return true;

}

bool handleGetBulkRequestPDU(ValueCallback* const *callbacks, int callbacksCount, const VarBind* varbindList, int varbindCount, VarBind outResponseList[], int &outResponseCount, unsigned int nonRepeaters, unsigned int maxRepititions, bool *outOverflow){
    SNMP_LOGD("handleGetBulkRequestPDU, nonRepeaters:%d, maxRepititions:%d, varbindSize:%d\n", nonRepeaters, maxRepititions, varbindCount);

    SNMP_LOGD("handling nonRepeaters\n");
    if(nonRepeaters > 0){
        unsigned int bound = (nonRepeaters < (unsigned int)varbindCount) ? nonRepeaters : (unsigned int)varbindCount;
        for(unsigned int i = 0; i < bound; i++){
            const VarBind& requestVarBind = varbindList[i];
            ValueCallback* callback = ValueCallback::findCallback(callbacks, callbacksCount, requestVarBind.oid, true);
            if(!callback){
                if(!appendResponseVarBind(outResponseList, outResponseCount, requestVarBind, pool_asn_sp(asn_new<ImplicitNullType>(ENDOFMIBVIEW)))){
                    *outOverflow = true;
                    return false;
                }
                continue;
            }

            AsnPtr<BER_CONTAINER> value = ValueCallback::getValueForCallback(callback);
            if(!value){
                SNMP_LOGD("Couldn't get value for callback\n");
                if(!appendResponseVarBind(outResponseList, outResponseCount, callback->OID, GEN_ERR)){
                    *outOverflow = true;
                    return false;
                }
                continue;
            }
            if(!appendResponseVarBind(outResponseList, outResponseCount, requestVarBind, std::move(value))){
                *outOverflow = true;
                return false;
            }
        }
    }

    if(varbindCount > (int)nonRepeaters){
        SNMP_LOGD("handling repeaters\n");
        unsigned int repeatingVarBinds = varbindCount - nonRepeaters;

        for(unsigned int i = 0; i < repeatingVarBinds; i++){
            OIDType* oid = varbindList[i+nonRepeaters].oid->cloneRaw();
            int foundAt = 0;

            for(unsigned int j = 0; j < maxRepititions; j++){
                SNMP_LOGD("finding next callback for OID: %s\n", oid->string());
                ValueCallback* callback = ValueCallback::findCallback(callbacks, callbacksCount, oid, true, foundAt, &foundAt);
                if(!callback){
                    if(!appendResponseVarBind(outResponseList, outResponseCount, oid, pool_asn_sp(asn_new<ImplicitNullType>(ENDOFMIBVIEW)))){
                        /* append did not consume oid on overflow — free it. */
                        asn_delete(oid);
                        *outOverflow = true;
                        return false;
                    }
                    oid = nullptr;
                    break;
                }

                AsnPtr<BER_CONTAINER> value = ValueCallback::getValueForCallback(callback);

                if(!value){
                    SNMP_LOGD("Couldn't get value for callback\n");
                    if(!appendResponseVarBind(outResponseList, outResponseCount, callback->OID, GEN_ERR)){
                        asn_delete(oid);
                        *outOverflow = true;
                        return false;
                    }
                    break;
                }

                if(!appendResponseVarBind(outResponseList, outResponseCount, callback->OID, std::move(value))){
                    asn_delete(oid);
                    *outOverflow = true;
                    return false;
                }

                asn_delete(oid);
                oid = callback->OID->cloneRaw();
            }

            asn_delete(oid);
        }
    }

    return true;
}