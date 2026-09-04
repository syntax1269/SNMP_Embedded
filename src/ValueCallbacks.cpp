#include "include/ValueCallbacks.h"
#include "include/BER.h"

#include <algorithm>

template <typename T>
static void pool_asn_deleter(T* p) noexcept {
    asn_delete(static_cast<BER_CONTAINER*>(p));
}

template <typename T>
static inline std::shared_ptr<T> pool_shared(T* p) noexcept {
    if(!p) return nullptr;
    return std::shared_ptr<T>(p, pool_asn_deleter<T>);
}

#define ASSERT_VALID_VALUE(value) if(!value) return nullptr;

#define SETTING_NON_SETTABLE_ERROR READ_ONLY
// If the value to be set is invalid
#define ASSERT_VALID_SETTABLE_VALUE(value) if(!value) return GEN_ERR;
#define ASSERT_VALID_SETTING_VALUE(value) if(!value) return WRONG_VALUE;

// If we ever remove the setting pre-check, use this
// #define ASSERT_CALLBACK_SETTABLE if(!(static_cast<ValueCallback*>(this)->isSettable)) return SETTING_NON_SETTABLE_ERROR;
#define ASSERT_CALLBACK_SETTABLE()

const char* ValueCallback::getTypeName(ASN_TYPE t) noexcept {
    switch(t){
        case INTEGER:    return "Integer";
        case STRING:     return "String";
        case NULLTYPE:   return "Null";
        case ASN_TYPE::OID: return "OID";
        case COUNTER32:  return "Counter32";
        case GAUGE32:    return "Gauge32";
        case TIMESTAMP:  return "Timestamp";
        case OPAQUE:     return "Opaque";
        case COUNTER64:  return "Counter64";
        default:         return "Unknown";
    }
}

ValueCallback* ValueCallback::findCallback(ValueCallback* const *callbacks, int callbacksCount, const OIDType* const oid, bool walk, int startAt, int *foundAt){
    bool useNext = false;

    for(int i = startAt; i < callbacksCount; i++){
        auto callback = callbacks[i];

        if(useNext){
            if(foundAt){
                *foundAt = i;
            }
            return callback;
        }

        if(oid->equals(callback->OID)){
            if(walk){
                useNext = true;
                continue;
            }
            if(foundAt){
                *foundAt = i;
            }
            return callback;
        }

        if(walk && callback->OID->isSubTreeOf(oid)){
            if(foundAt){
                *foundAt = i;
            }
            return callback;
        }
    }
    return nullptr;
}

std::shared_ptr<BER_CONTAINER> ValueCallback::getValueForCallback(ValueCallback* callback){
    SNMP_LOGD("Getting value for callback of OID: %s, type: %d\n", callback->OID->string(), callback->type);
    auto value = callback->buildTypeWithValue();
    return value;
}

SNMP_ERROR_STATUS ValueCallback::setValueForCallback(ValueCallback* callback, const std::shared_ptr<BER_CONTAINER> &value){
    SNMP_LOGD("Setting value for callback of OID: %s\n", callback->OID->string());

    if(!callback->isSettable){
        return SETTING_NON_SETTABLE_ERROR;
    }

    callback->setOccurred = true;
    SNMP_ERROR_STATUS valid = callback->setTypeWithValue(value.get());
    if(valid != NO_ERROR){
        callback->setOccurred = false;
    }

    return valid;
}

std::shared_ptr<BER_CONTAINER> IntegerCallback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    auto val = pool_shared(asn_new<IntegerType>(*this->value));
    if(!val) return nullptr;
    if(this->modifier != 0){
        val->_value /= this->modifier;
    }
    return val;
}

SNMP_ERROR_STATUS IntegerCallback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    IntegerType* val = static_cast<IntegerType*>(rawValue);
    if(this->modifier){
        // Apple local division if callback was asked to
        // val->_value /= this->modifier;
    }
    *this->value = val->_value;

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> TimestampCallback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return pool_shared(asn_new<TimestampType>(*this->value));
}

SNMP_ERROR_STATUS TimestampCallback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    TimestampType* val = static_cast<TimestampType*>(rawValue);
    *this->value = val->_value;

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> StringCallback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return pool_shared(asn_new<OctetType>(*this->value));
}

SNMP_ERROR_STATUS StringCallback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    OctetType* val = static_cast<OctetType*>(rawValue);
    if(val->_valueLen >= this->max_len) return WRONG_LENGTH;
    strncpy(*this->value, val->_value, this->max_len);

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> ReadOnlyStringCallback::buildTypeWithValue(){
    return pool_shared(asn_new<OctetType>(this->value));
}


std::shared_ptr<BER_CONTAINER> OpaqueCallback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return pool_shared(asn_new<OpaqueType>(this->value, this->data_len));
}

SNMP_ERROR_STATUS OpaqueCallback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    OpaqueType* val = static_cast<OpaqueType*>(rawValue);
    ASSERT_VALID_SETTING_VALUE(val->_value);
    if(val->_dataLength > this->data_len) return WRONG_LENGTH;
    memcpy(this->value, val->_value, this->data_len);

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> OIDCallback::buildTypeWithValue(){
    auto oid = pool_shared(asn_new<OIDType>(this->value));
    if(!oid || !oid->valid) return nullptr;
    return oid;
}

std::shared_ptr<BER_CONTAINER> Counter32Callback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return pool_shared(asn_new<Counter32>(*this->value));
}

SNMP_ERROR_STATUS Counter32Callback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    Counter32* val = static_cast<Counter32*>(rawValue);
    uint32_t incoming = (uint32_t)val->_value;
    if(*this->value != incoming){
        *this->value = incoming;
    } else {
        this->setOccurred = false;
    }
    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> Gauge32Callback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return pool_shared(asn_new<Gauge>(*this->value));
}

SNMP_ERROR_STATUS Gauge32Callback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    Gauge* val = static_cast<Gauge*>(rawValue);
    *this->value = val->_value;

    return NO_ERROR;
}

std::shared_ptr<BER_CONTAINER> Counter64Callback::buildTypeWithValue(){
    ASSERT_VALID_VALUE(this->value);

    return pool_shared(asn_new<Counter64>(*this->value));
}

SNMP_ERROR_STATUS Counter64Callback::setTypeWithValue(BER_CONTAINER* rawValue){
    ASSERT_CALLBACK_SETTABLE();
    ASSERT_VALID_SETTABLE_VALUE(this->value);

    Counter64* val = static_cast<Counter64*>(rawValue);
    if(*this->value != val->_value){
        *this->value = val->_value;
    } else {
        this->setOccurred = false;
    }
    return NO_ERROR;
}

bool SortableOIDType::sort_oids(const SortableOIDType* oid1, const SortableOIDType* oid2){
    if(!oid1 || !oid2) return false;
    if(oid1->dataLen == 0) return false;
    if(oid2->dataLen == 0) return true;

    const uint8_t* p1 = oid1->data;
    const uint8_t* p2 = oid2->data;
    int rem1 = oid1->dataLen;
    int rem2 = oid2->dataLen;

    while(rem1 > 0 && rem2 > 0){
        long sub1 = 0;
        long sub2 = 0;
        int consumed1 = 0;
        int consumed2 = 0;
        do {
            sub1 = (sub1 << 7) | (*p1 & 0x7F);
            consumed1++;
        } while(rem1-- > 0 && (*p1++ & 0x80) != 0);
        do {
            sub2 = (sub2 << 7) | (*p2 & 0x7F);
            consumed2++;
        } while(rem2-- > 0 && (*p2++ & 0x80) != 0);
        (void)consumed1; (void)consumed2;
        if(sub1 != sub2) return sub1 < sub2;
    }
    if(rem1 > 0) return false;
    if(rem2 > 0) return true;
    return false;
}

bool compare_callbacks (const ValueCallback* first, const ValueCallback* second){
    return SortableOIDType::sort_oids(first->OID, second->OID);
}

void sort_handlers(ValueCallback** callbacks, int callbacksCount){
    if(callbacksCount <= 1) return;
    std::sort(callbacks, callbacks + callbacksCount, compare_callbacks);
}

bool remove_handler(ValueCallback** callbacks, int& callbacksCount, ValueCallback* callback){
    int i = 0;
    int found = -1;
    for(i = 0; i < callbacksCount; i++){
        if(callbacks[i] == callback){
            found = i;
            break;
        }
    }

    if(found > -1){
        for(int j = found; j < callbacksCount - 1; j++){
            callbacks[j] = callbacks[j + 1];
        }
        callbacks[callbacksCount - 1] = nullptr;
        callbacksCount--;
        return true;
    } else {
        return false;
    }
}