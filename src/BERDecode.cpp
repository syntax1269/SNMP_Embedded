#include "include/BER.h"
#ifdef COMPILING_TESTS
    #include "tests/required/millis.h"   /* host shim: millis() -> 0 (real millis comes via Arduino.h) */
#endif

#ifndef SNMP_POOLS_IN_BSS
    /* Allocate the ASNPool storage once at startup (first asn_new call).
       Count and layout are fixed at compile time — never reallocated, never
       grown, complying with the "heap only at init, zero runtime growth"
       rule.  This moves ~25 KB of static BSS (.bss) into the heap on
       ESP8266 tiny profiles, restoring WiFi/LittleFS/ArduinoJson headroom. */
    ASNPool::Slot* ASNPool::slots = nullptr;
    bool ASNPool::_poolsReady = false;

    void ASNPool::_ensurePools() {
        if(_poolsReady) return;
        /* operator new[] calls each Slot's default ctor; Slot is trivially
           default-constructible (alignas char[N] array + bool) so we get
           zero-initialized occupied and untouched storage bytes as required. */
        slots = new Slot[SNMP_POOL_ASN_OBJECTS]();
        _poolsReady = true;
    }

    /* v3.3.0: pre-allocate the arena at the earliest safe moment. Called from
     * the SNMPAgent constructor (global-ctor time on Arduino sketches — before
     * setup(), before WiFi) so the one contiguous arena is claimed while the
     * heap is pristine. Same one-shot as _ensurePools, but no-throw: a failure
     * here logs and leaves the lazy path armed instead of aborting the sketch
     * (ESP8266 runs with exceptions disabled — a throwing new = abort). */
    void ASNPool::lockInArena() {
#if SNMP_POOL_LOCK_AT_BOOT
        if(_poolsReady) return;
        slots = new (std::nothrow) Slot[SNMP_POOL_ASN_OBJECTS]();
        if(slots){
            _poolsReady = true;
            lockInMs = millis();
            SNMP_LOGI("ASNPool: arena locked in at boot: %d slots x %d B = %d B, one contiguous block (ctor t=%lu ms)\n",
                      (int)SNMP_POOL_ASN_OBJECTS, (int)sizeof(Slot),
                      (int)(sizeof(Slot) * SNMP_POOL_ASN_OBJECTS), (unsigned long)lockInMs);
        } else {
            SNMP_LOGW("ASNPool: boot lock-in FAILED (heap too fragmented at ctor time) - falling back to lazy first-use allocation\n");
        }
#endif
    }
#else
    ASNPool::Slot ASNPool::slots[SNMP_POOL_ASN_OBJECTS] = {};
#endif
int ASNPool::usedCount = 0;
int ASNPool::permCount = 0;
int ASNPool::usedCountPeak = 0;
bool ASNPool::permFrozen = false;
uint32_t ASNPool::lockInMs = 0;
int ASNPool::doubleReleaseAlarms = 0;

void ASNPool::release(BER_CONTAINER* p){
    if(!p) return;
#ifndef SNMP_POOLS_IN_BSS
    if(!_poolsReady) { delete p; return; }
#endif
    /* Double-release guard: without it, a double-destroyed object re-runs its
     * destructor AND decrements usedCount twice. The counter then under-reports
     * occupancy, rawAlloc() reuses a slot that still holds a live object, and
     * live OIDs get corrupted — the root cause of degraded GetBulk responses
     * and the "agent goes deaf" incidents documented during the reliability
     * campaign. */
    for(int i = 0; i < SNMP_POOL_ASN_OBJECTS; i++){
        if(static_cast<void*>(slots[i].storage) == static_cast<void*>(p)){
            if(!slots[i].occupied){
                /* Destroy of an already-released slot.  v3.3.3: distinguish
                 * the two cases:
                 *  - bulkFreed: the slot was flag-freed by resetAll() while a
                 *    live pointer remained (trap rebuild pattern: buildForSending
                 *    -> sendTo's resetAll -> rebuild; the surviving stale
                 *    asn_delete(this->packet) in the next rebuild is the
                 *    sanctioned shape).  Silent return - not a caller bug.
                 *    Not consumed: repeated stale deletes stay silent until
                 *    the slot is reallocated (rawAlloc clears bulkFreed).
                 *  - not bulkFreed: the slot was released by a normal
                 *    asn_delete and is being destroyed AGAIN - a true caller
                 *    double-destroy (the double-release bug class).
                 *    One-shot alarm per slot + doubleReleaseAlarms counter;
                 *    host tests assert the counter stays 0. */
                if(slots[i].bulkFreed){
                    return;
                }
                if(!slots[i].doubleReleaseWarned){
                    slots[i].doubleReleaseWarned = true;
                    doubleReleaseAlarms++;
                    SNMP_LOGE("ASNPool: DOUBLE RELEASE of slot %d detected (caller destroying an object twice)\n", i);
                }
                return;
            }
            p->~BER_CONTAINER();
            slots[i].occupied = false;
            usedCount--;
            return;
        }
    }
}

void asn_delete(BER_CONTAINER* p){
    if(!p) return;
    if(ASNPool::isInPool(static_cast<const void*>(p))){
        ASNPool::release(p);
    } else {
        delete p;
    }
}
// Two ways to decode an int, one way where the first byte indicates how many butes follow, and ne where you have to power things by 128
static size_t decode_ber_longform_integer(const uint8_t* buf, long* decoded_integer, int max_len){
    int i = 1;
    long running_length = 0;
    while(*buf >= 128 && i < max_len && running_length < INT_MAX){
        running_length += *buf & 0x7F;
        running_length *= 128;
        buf++;
        i++;
    }
    running_length += *buf; // the lone byte
    *decoded_integer = running_length;
    return i;
}

static size_t decode_ber_length_integer(const uint8_t* buf, int* decoded_integer, int){
    if(*buf <= 127) {
        *decoded_integer = *buf;
        return 1;
    } else {
        int numBytes = *buf & 0x7F;
        int special_length = 0;
        for(int k = 0; k < numBytes; k++){
            buf++;
            special_length <<= 8;
            special_length |= *buf;
        }
        *decoded_integer = special_length;
        return numBytes + 1;
    }
}

int BER_CONTAINER::fromBuffer(const uint8_t *buf, size_t max_len) {
    if(max_len < 2) return SNMP_BUFFER_ERROR_TLV_TOO_SMALL;

    const uint8_t* ptr = buf;
    if(*ptr != _type){
        SNMP_LOGE("Mismatched type when decoding %d, %d\n", _type, *ptr);
        return SNMP_BUFFER_ERROR_TYPE_MISMATCH;
    }
    ptr++;
    ptr += decode_ber_length_integer(ptr, &_length, (int)max_len - 1);
    int header_len = static_cast<int>(ptr - buf);
    if(static_cast<size_t>(_length) + header_len > max_len){
        return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;
    }

    return header_len;
}

int NetworkAddress::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);
    const uint8_t* ptr = buf + i;

    // byte tempAddress[4];
    // tempAddress[0] = *ptr++;
    // tempAddress[1] = *ptr++;
    // tempAddress[2] = *ptr++;
    // tempAddress[3] = *ptr++;

    _value = IPAddress(ptr);
    return ptr - buf;
}

int IntegerType::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);
    const uint8_t* ptr = buf + i;

    unsigned short tempLength = _length;
    uint32_t tempVal = 0; 

    while(tempLength > 0){
        tempVal = tempVal << 8;
        tempVal = tempVal | *ptr++;
        tempLength--;
    }

    switch(_length){
        case 1:
            _value = (int8_t)tempVal;
        break;
        case 2:
            _value = (int16_t)tempVal;
        break;
        case 3:
            if(tempVal & 0x00800000){
                tempVal |= 0xFF000000;
            }
            _value = (int32_t)tempVal;
        break;
        default:
            _value = (int32_t)tempVal;
    }
    
    return ptr - buf;
}

int OctetType::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);
    const uint8_t* ptr = buf + i;
    if(_length > OCTET_TYPE_MAX_LENGTH) return SNMP_BUFFER_ERROR_OCTET_TOO_BIG;

    if(_length > (int)SNMP_MAX_STRING_LEN) _length = (int)SNMP_MAX_STRING_LEN;
    memcpy(_value, ptr, _length);
    _value[_length] = 0;
    _valueLen = _length;

    return _length + i;
}

int OpaqueType::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);

    if(_length > (int)sizeof(this->_value)) {
        return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;
    }

    if(static_cast<size_t>(i + _length) > max_len) {
        return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;
    }

    const uint8_t* ptr = buf + i;
    if(_length > 0) {
        memcpy(this->_value, ptr, (size_t)_length);
    }
    _dataLength = _length;

    return i + _length;
}

int OIDType::fromBuffer(const uint8_t *buf, size_t max_len){
    int j = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(j);

    if(_length > (int)sizeof(this->data)) return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;
    if(static_cast<size_t>(j + _length) > max_len) return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;

    const uint8_t* dataPtr = buf + j;
    if(*dataPtr != 0x2b) return SNMP_BUFFER_ERROR_INVALID_OID;

    if(_length > 0) memcpy(this->data, dataPtr, (size_t)_length);
    this->dataLen = _length;
    this->valid = true;

    return j + _length;
}

static inline void long_to_buf(char* buf, long l, short r = 0){
    if (l > 9){
        long_to_buf(buf++, l / 10L, r + 1);
    }
    *buf++ = l % 10 + '0';
    if(!r) *buf = 0;
}

const char* OIDType::string() {
    if(_valueStr[0] == 0){
        const uint8_t* dataPtr = this->data;

        size_t pos = 0;
        const char* prefix = ".1.3";
        size_t prefixLen = strlen(prefix);
        if(pos + prefixLen <= SNMP_MAX_OID_STR_LEN){
            memcpy(_valueStr + pos, prefix, prefixLen);
            pos += prefixLen;
        }
        _valueStr[pos] = 0;
        if(!this->valid) return _valueStr;

        dataPtr++;

        int i = this->dataLen - 1;
        char buffer[16];

        while(i > 0){
            memset(buffer, 0, sizeof(buffer));
            long item = 0;
            int itemLength = decode_ber_longform_integer(dataPtr, &item, i);
            dataPtr += itemLength; i -= itemLength;

            buffer[0] = '.';
            long_to_buf(buffer+1, item);
            size_t buflen = strlen(buffer);
            if(pos + buflen <= SNMP_MAX_OID_STR_LEN){
                memcpy(_valueStr + pos, buffer, buflen);
                pos += buflen;
            }
            _valueStr[pos] = 0;
        }
    }
    return _valueStr;
}

int NullType::fromBuffer(const uint8_t *, size_t){
    _length = 0;
    return 2;
}

int Counter64::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);

    if(static_cast<size_t>(i + _length) > max_len) return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;

    const uint8_t* ptr = buf + i;

    int tempLength = _length;
    _value = 0;
    while(tempLength > 0){
        _value = _value << 8U;
        _value = _value | *ptr++;
        tempLength--;
    }
    return i + _length;
}

BER_CONTAINER* ComplexType::createObjectForType(ASN_TYPE valueType){
    SNMP_LOGD("Creating object of type: %d\n", valueType);
    switch(valueType){
        case INTEGER:
            return asn_new<IntegerType>();
        case STRING:
            return asn_new<OctetType>();
        case OID: 
            return asn_new<OIDType>();
        case NULLTYPE:
            return asn_new<NullType>();

        case NOSUCHOBJECT:
            return asn_new<ImplicitNullType>(NOSUCHOBJECT);
        case NOSUCHINSTANCE:
            return asn_new<ImplicitNullType>(NOSUCHINSTANCE);
        case ENDOFMIBVIEW:
            return asn_new<ImplicitNullType>(ENDOFMIBVIEW);

        case NETWORK_ADDRESS:
            return asn_new<NetworkAddress>();
        case TIMESTAMP:
            return asn_new<TimestampType>();
        case COUNTER32:
            return asn_new<Counter32>();
        case GAUGE32:
            return asn_new<Gauge>();
        case COUNTER64:
            return asn_new<Counter64>();
        case OPAQUE:
            return asn_new<OpaqueType>();

        case STRUCTURE:

        case GetRequestPDU:
        case GetNextRequestPDU:
        case GetResponsePDU:
        case SetRequestPDU:
        case GetBulkRequestPDU:

        case InformRequestPDU:
        case Trapv2PDU:
            return asn_new<ComplexType>(valueType);
        default:
            return nullptr;
    }
}

int ComplexType::fromBuffer(const uint8_t *buf, size_t max_len){
    int j = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(j);

    if(static_cast<size_t>(j + _length) > max_len) return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;

    const uint8_t* ptr = buf + j;
    size_t outer_used = static_cast<size_t>(j);

    this->_ownsChildren = true;  /* children are new'd here; we own them */

    int remaining = _length;
    while(remaining > 0){
        ASN_TYPE valueType = (ASN_TYPE)*ptr;

        if(this->valuesLen >= SNMP_MAX_COMPLEX_CHILDREN) {
            return SNMP_BUFFER_ERROR_UNKNOWN_TYPE;   /* too many VBs; well-defined error */
        }

        BER_CONTAINER* newObj = ComplexType::createObjectForType(valueType);
        if(!newObj){
            SNMP_LOGD("Couldn't create object of type: %d\n", valueType);
            return SNMP_BUFFER_ERROR_UNKNOWN_TYPE;
        }

        int used_length = newObj->fromBuffer(ptr, max_len - outer_used);
        if(used_length < 0){
            asn_delete(newObj);
            SNMP_LOGD("Problem deserialising structure of type: %d\n", valueType);
            return SNMP_BUFFER_ERROR_PROBLEM_DESERIALISING;
        }

        this->values[this->valuesLen++] = newObj;

        ptr += used_length;
        remaining -= used_length;
        outer_used += static_cast<size_t>(used_length);
    }
    return j + _length;
}