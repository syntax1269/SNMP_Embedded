#ifndef BER_h
#define BER_h

#include <math.h>
#include <utility>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <new>

#ifdef COMPILING_TESTS
    #include "tests/required/IPAddress.h"
    #include "tests/required/UDP.h"
#else
    #include <Arduino.h>
    #include "IPAddress.h"
#endif

#include <memory>
#include "include/defs.h"

#define ASN_POOL_MAX(a,b) ((a)>(b)?(a):(b))

class BER_CONTAINER;

struct ASNPool {
#ifndef SNMP_POOL_SLOT_SIZE
#define SNMP_POOL_SLOT_SIZE 640
#endif

    struct Slot {
        alignas(8) char storage[SNMP_POOL_SLOT_SIZE];
        bool occupied;
        bool doubleReleaseWarned;   /* one-shot alarm latch for DEBUG>0 */
        bool bulkFreed;             /* v3.3.3: freed by resetAll() while a pointer was still live
                                       (trap rebuild pattern: build -> sendTo resetAll -> rebuild).
                                       A stale asn_delete() of such a slot is EXPECTED, not a bug. */
    };

    /* SNMP_POOLS_IN_BSS = 1 forces ASNPool storage back to static .bss.
       Leave it undefined (default) to allocate slots on the heap exactly
       once at first asn_new<>().  Startup-time heap allocation is allowed
       per project rules: size fixed at compile-time, never realloc, never
       grows at runtime.  Frees ~20-40 KB of BSS for ESP8266/ESP8266 parts
       whose DRAM budget is 64-80 KB once WiFi + libraries are linked. */
#ifndef SNMP_POOLS_IN_BSS
    static Slot* slots;          // malloc once at first rawAlloc()
    static bool _poolsReady;     // true after one-shot init
    static void _ensurePools();  // one-shot new Slot[N]; memset 0
#else
    static Slot slots[SNMP_POOL_ASN_OBJECTS];
#endif
    static int usedCount;
    static int permCount;
    static int usedCountPeak;   /* high-water mark since boot — diagnostics */
    static int doubleReleaseAlarms; /* v3.3.3: count of TRUE double-destroy alarms (not bulkFree stale deletes) — host-test verification */
    static bool permFrozen;     /* true once the startup baseline is frozen */
    static uint32_t lockInMs;   /* v3.3.0: millis() reading when the arena was pre-allocated (0 = not locked at ctor time / static BSS) */

    /* v3.3.0: pre-allocate the arena NOW. Designed to run inside the SNMPAgent
     * constructor — global-ctor time, before setup() and WiFi — when the heap
     * is pristine and one contiguous arena is trivially available. No-throw:
     * on failure logs and leaves the lazy path armed. Idempotent. */
    static void lockInArena();

    static inline void freezePermCount() noexcept {
        int high = 0;
        for(int i = 0; i < SNMP_POOL_ASN_OBJECTS; i++){
            if(slots[i].occupied) high = i + 1;
        }
        permCount = high;
        usedCount = high < usedCount ? high : usedCount;
        permFrozen = true;
    }

    /* One-shot safety net for sketches that never call
     * freezePermCount() in setup (all shipped examples). Freezing the startup
     * baseline before the first transient allocation prevents resetAll() from
     * marking permanently-registered callback OIDs as free — a live-object
     * reuse that corrupted response OIDs on ESP8266 ('.1.3' truncation,
     * valid=false, ret=-2, agent deaf). Explicit freezePermCount() calls
     * remain supported and simply make this a no-op. */
    static inline void autoFreezePermCountOnce() noexcept {
        if(permFrozen) return;
        freezePermCount();
        SNMP_LOGI("ASNPool: startup baseline auto-frozen at %d/%d slots (sketch did not call freezePermCount)\n",
                  permCount, (int)SNMP_POOL_ASN_OBJECTS);
    }

    static inline bool isInPool(const void* p){
#ifndef SNMP_POOLS_IN_BSS
        if(!_poolsReady) return false;
#endif
        const char* pc = static_cast<const char*>(p);
        const char* base = static_cast<const char*>(static_cast<const void*>(slots[0].storage));
        const char* end  = static_cast<const char*>(static_cast<const void*>(slots[SNMP_POOL_ASN_OBJECTS].storage));
        if(pc < base || pc >= end) return false;
        size_t off = (size_t)(pc - base);
        return (off % sizeof(Slot)) == offsetof(Slot, storage);
    }

    static void* rawAlloc(size_t sz){
        if(sz > SNMP_POOL_SLOT_SIZE) {
            SNMP_LOGE("ASNPool::rawAlloc: request %zu B > slot %d B\n", sz, (int)SNMP_POOL_SLOT_SIZE);
            return nullptr;
        }
#ifndef SNMP_POOLS_IN_BSS
        if(!_poolsReady) _ensurePools();
#endif
        if(usedCount >= SNMP_POOL_ASN_OBJECTS){
            SNMP_LOGE("ASNPool EXHAUSTED: %d/%d slots in use (%d B/slot). Raise SNMP_POOL_ASN_OBJECTS. First NULL deref = Exception 28.\n",
                      usedCount, (int)SNMP_POOL_ASN_OBJECTS, (int)SNMP_POOL_SLOT_SIZE);
            return nullptr;
        }
        for(int i = 0; i < SNMP_POOL_ASN_OBJECTS; i++){
            if(!slots[i].occupied){
                slots[i].occupied = true;
                slots[i].bulkFreed = false;   /* fresh tenancy: stale-delete grace no longer applies */
                usedCount++;
                if(usedCount > usedCountPeak) usedCountPeak = usedCount;
                return slots[i].storage;
            }
        }
        SNMP_LOGE("ASNPool EXHAUSTED: %d/%d slots in use (%d B/slot). Raise SNMP_POOL_ASN_OBJECTS. First NULL deref = Exception 28.\n",
                  usedCount, (int)SNMP_POOL_ASN_OBJECTS, (int)SNMP_POOL_SLOT_SIZE);
        return nullptr;
    }

    static void release(BER_CONTAINER* p);

    static inline void resetAll() noexcept {
#ifndef SNMP_POOLS_IN_BSS
        if(!_poolsReady) return;
#endif
        /* resetAll() is the single choke point every pool-reset caller
         * goes through (SNMPTrap::sendTo, SNMPAgent::loop, inform teardown).
         * Guaranteeing the startup baseline HERE (not in loop()) is what makes
         * it path-independent: a sketch that sends a trap before its first
         * loop() tick previously reset the pool while permCount was still 0,
         * freeing the permanently-registered callback OIDs and letting the
         * trap build clobber them (corrupt '.1.3' response OIDs, agent deaf
         * — root cause of the CMP-comparison walk failures). */
        autoFreezePermCountOnce();
        for(int i = permCount; i < SNMP_POOL_ASN_OBJECTS; i++){
            /* v3.3.3: mark WHY the slot was freed.  A live object may still be
             * pointed at (trap tree survives this reset for its rebuild), and
             * its later asn_delete() is the sanctioned stale-delete pattern. */
            if(slots[i].occupied) slots[i].bulkFreed = true;
            slots[i].occupied = false;
        }
        usedCount = permCount;
    }
};

template<typename T, typename... Args>
static inline T* asn_new(Args&&... args){
    void* slot = ASNPool::rawAlloc(sizeof(T));
    if(slot){
        T* obj = ::new (slot) T(std::forward<Args>(args)...);
        return obj;
    }
#ifdef COMPILING_TESTS
    /* Native host tests: pool capacity is a logic stress-test vector, not a
       hard safety bound.  Host has GB of free RAM so falling back to operator
       new allows 101/101 Catch2 assertions to exercise logic end-to-end without
       needing an enormous static pool.  On real MCU targets (COMPILING_TESTS
       undefined) we strictly return nullptr = zero hot-path heap. */
    return ::new T(std::forward<Args>(args)...);
#else
    return nullptr;
#endif
}

void asn_delete(BER_CONTAINER* p);

/* v3.4.2: deep-clone any BER_CONTAINER into a fresh pool object (switch on
 * _type).  Returns nullptr for a null src or on pool exhaustion.  Used by
 * the deprecated buildTypeWithValue() bridge (the legacy shared_ptr cannot
 * be disarmed, so its value is cloned out) and available to any caller that
 * needs container duplication without knowing the concrete class. */
BER_CONTAINER* asn_clone(const BER_CONTAINER* src);

/* ========================================================================
 * v3.4.2 — AsnPtr<T>: move-only owning pointer for pool-allocated ASN
 * containers.  Replaces std::shared_ptr in the packet hot path.
 *
 * WHY IT EXISTS (Report_001 finding #1): a shared_ptr built from a raw
 * pointer always heap-allocates a control block (~16-32 B: refcounts,
 * deleter, vptr).  Pool-allocating the pointee does not make the
 * bookkeeping heap-free — so "zero per-packet heap traffic" was not true
 * while the hot path built shared_ptrs.  AsnPtr has exactly one member
 * (the pointer) and routes destruction through the existing asn_delete(),
 * so the pool's occupancy machinery IS the ownership record — nothing is
 * added to ASNPool::Slot and nothing touches the heap.
 *
 * OWNERSHIP MODEL: move-only, single owner, no refcount.  Verified against
 * the whole tree: no shared_ptr in the packet path ever shares — VarBind
 * deep-clones shared_ptr content into its own raw owning pointer, the
 * inform queue is stateless (pool freed at each send), and every shared_ptr
 * is confined to one function scope or one packet's lifetime.  Move-only
 * makes the historic bug class (pool address handed to plain delete)
 * structurally impossible: the only destruction path is asn_delete.
 *
 * LIFETIME CONTRACT: identical to the shared_ptr+PoolDeleter scheme it
 * replaces — asn_delete() tolerates stale (bulkFreed) slots silently and
 * alarms only on true double-destroy; all v3.3.3 pool tests carry over
 * unchanged.
 * ======================================================================== */
template<typename T>
class AsnPtr {
    T* p_;
public:
    explicit AsnPtr(T* raw = nullptr) noexcept : p_(raw) {}
    /* non-explicit: `return nullptr;` in a factory means "empty" exactly as
     * it did in the shared_ptr era. */
    AsnPtr(std::nullptr_t) noexcept : p_(nullptr) {}
    ~AsnPtr(){ if(p_){ asn_delete(static_cast<BER_CONTAINER*>(p_)); p_ = nullptr; } }

    AsnPtr(const AsnPtr&) = delete;
    AsnPtr& operator=(const AsnPtr&) = delete;

    AsnPtr(AsnPtr&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
    AsnPtr& operator=(AsnPtr&& o) noexcept {
        if(this != &o){
            if(p_) asn_delete(static_cast<BER_CONTAINER*>(p_));
            p_ = o.p_; o.p_ = nullptr;
        }
        return *this;
    }

    T* get() const noexcept { return p_; }
    T* operator->() const noexcept { return p_; }
    T& operator*() const noexcept { return *p_; }
    explicit operator bool() const noexcept { return p_ != nullptr; }

    /* Explicit ownership transfer OUT of the guard (raw pointer handed to
     * a raw-owning API, e.g. VarBind's owning value_ member).  The guard
     * is disarmed: the caller now owns the object. */
    T* release() noexcept { T* p = p_; p_ = nullptr; return p; }

    /* Explicit ownership transfer IN (disarms the source). */
    void reset(T* raw = nullptr) noexcept {
        if(p_ != raw){
            if(p_) asn_delete(static_cast<BER_CONTAINER*>(p_));
            p_ = raw;
        }
    }
    void swap(AsnPtr& o) noexcept { T* t = p_; p_ = o.p_; o.p_ = t; }
};

typedef enum ASN_TYPE_WITH_VALUE {
    // Primatives
    INTEGER = 0x02,
    STRING = 0x04,
    NULLTYPE = 0x05,
    OID = 0x06,
    
    // Complex
    STRUCTURE = 0x30,
    NETWORK_ADDRESS = 0x40,
    COUNTER32 = 0x41,
    GAUGE32 = 0x42,
    USIGNED32 = 0x42, // Same as Gauge32
    TIMESTAMP = 0x43,
    OPAQUE = 0x44,
	COUNTER64 = 0x46,

    /*
        FROM: RFC3416
    */
    NOSUCHOBJECT = 0x80,
    NOSUCHINSTANCE = 0x81,
    ENDOFMIBVIEW = 0x82,
    
    // Structure Types
    GetRequestPDU = 0xA0,
    GetNextRequestPDU = 0xA1,
    GetResponsePDU = 0xA2,
    SetRequestPDU = 0xA3,
    TrapPDU = 0xA4,
    GetBulkRequestPDU = 0xA5,
    InformRequestPDU = 0xA6,
    Trapv2PDU = 0xA7
    
} ASN_TYPE;

#define ASN_PDU_TYPE_MIN_VALUE GetRequestPDU
#define ASN_PDU_TYPE_MAX_VALUE Trapv2PDU

#define MAX_DYNAMIC_ASN_TYPE COUNTER64

typedef int SNMP_BUFFER_PARSE_ERROR;
typedef int SNMP_BUFFER_ENCODE_ERROR;

#define SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED (-1 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_TLV_TOO_SMALL (-2 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_PROBLEM_DESERIALISING (-3 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_UNKNOWN_TYPE (-4 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_TYPE_MISMATCH (-5 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_OCTET_TOO_BIG (-6 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_INVALID_OID (-7 + SNMP_BUFFER_PARSE_ERROR_OFFSET)

#define SNMP_BUFFER_ENCODE_ERR_LEN_EXCEEDED (-1 + SNMP_BUFFER_ENCODE_ERROR_OFFSET)
#define SNMP_BUFFER_ENCODE_ERROR_INVALID_ITEM (-2 + SNMP_BUFFER_ENCODE_ERROR_OFFSET)
#define SNMP_BUFFER_ENCODE_ERROR_INVALID_OID (-7 + SNMP_BUFFER_ENCODE_ERROR_OFFSET)

#define CHECK_DECODE_ERR(i) if((i) < 0) return i
#define CHECK_ENCODE_ERR(i) if((i) < 0) return i

// primitive types inherits straight off the container, complex come off complexType
// all primitives have to serialiseInto themselves (type, length, data), to be put straight into the packet.
// for deserialising, from the parent container we check the type, then create anobject of that type and calls deSerialise, passing in the data, which pulls it out and saves, and if complex, first split up it schildren into seperate BERs, then creates and passes them creates a child with it's data using the same process.


class BER_CONTAINER {
  public:
    BER_CONTAINER(ASN_TYPE type) : _type(type){}
    virtual ~BER_CONTAINER()= default;    ASN_TYPE _type;
    int _length = 0;

#ifdef COMPILING_TESTS
    /* Host-test shim: public pass-through to the protected serialise so
     * byte-equivalence tests (v3.4.0 Phase 3 BerWriter vs containers) can
     * invoke any subclass's encoder directly.  Compiled out of production. */
    int testSerialise(uint8_t* buf, size_t max_len){ return serialise(buf, max_len); }
#endif

    /* v3.4.0 Phase 4: public pass-through to the protected serialise() for
     * the zero-copy response builder (a free function outside the class
     * hierarchy, compiled only under SNMP_ZERO_COPY=1).  Byte-identical to
     * serialise(); virtual dispatch reaches each subclass's encoder. */
    int wireSerialise(uint8_t* buf, size_t max_len){ return serialise(buf, max_len); }
    // Serialise object in BER notation into buf, with a maximum size of max_len; returns number of bytes used
    virtual int serialise(uint8_t* buf, size_t max_len);
    virtual int serialise(uint8_t* buf, size_t max_len, size_t known_length);

    // returns number of bytes used from buf, limited by max_len, return -1 if failed to parse
    virtual int fromBuffer(const uint8_t *buf, size_t max_len);

protected:

    friend class ComplexType;
    template<typename U, typename... Args> friend U* asn_new(Args&&... args);
};

class NetworkAddress: public BER_CONTAINER {
  public:
    NetworkAddress(): BER_CONTAINER(NETWORK_ADDRESS) {}
    explicit NetworkAddress(const IPAddress& ip): NetworkAddress(){
        _value = ip;
    }

    IPAddress _value = INADDR_NONE;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;
};


class IntegerType: public BER_CONTAINER {
  public:
    IntegerType(): BER_CONTAINER(INTEGER) {}
    explicit IntegerType(int value): IntegerType(){
        _value = value;
    }

    int _value = 0;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;
};

class TimestampType: public IntegerType {
  public:
    TimestampType(): IntegerType(){
        _type = TIMESTAMP;
    }
    explicit TimestampType(unsigned long value): IntegerType(value){
        _type = TIMESTAMP;
    }
};

class OctetType: public BER_CONTAINER {
  public:
    explicit OctetType(const char* value): BER_CONTAINER(STRING) {
        size_t len = strlen(value);
        if(len > SNMP_MAX_STRING_LEN) len = SNMP_MAX_STRING_LEN;
        memcpy(_value, value, len);
        _value[len] = 0;
        _valueLen = len;
    }
    OctetType(const char* value, size_t len): BER_CONTAINER(STRING) {
        if(len > SNMP_MAX_STRING_LEN) len = SNMP_MAX_STRING_LEN;
        memcpy(_value, value, len);
        _value[len] = 0;
        _valueLen = len;
    }

    char _value[SNMP_MAX_STRING_LEN + 1];
    size_t _valueLen = 0;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;

    OctetType(): BER_CONTAINER(STRING) { _value[0] = 0; }
    friend class ComplexType;
    template<typename U, typename... Args> friend U* asn_new(Args&&... args);
};

class OpaqueType: public BER_CONTAINER {
  public:
    OpaqueType(const uint8_t* value, int length): OpaqueType(){
        if(length > (int)sizeof(this->_value)) {
            length = (int)sizeof(this->_value);
        }
        if(length < 0) length = 0;
        if(length > 0 && value) {
            memcpy(this->_value, value, (size_t)length);
        } else {
            length = 0;
        }
        this->_dataLength = length;
    }

    uint8_t _value[OCTET_TYPE_MAX_LENGTH];
    int _dataLength = 0;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;

    OpaqueType(): BER_CONTAINER(OPAQUE) {
        this->_dataLength = 0;
    }
    friend class ComplexType;
    template<typename U, typename... Args> friend U* asn_new(Args&&... args);
};


class OIDType: public BER_CONTAINER {
  public:
    explicit OIDType(const char* value): BER_CONTAINER(OID) {
        size_t len = strlen(value);
        if(len > SNMP_MAX_OID_STR_LEN) len = SNMP_MAX_OID_STR_LEN;
        _init_from_cstr(value, len);
    }

    template<size_t N>
    OIDType(const char (&value)[N]): BER_CONTAINER(OID) {
        constexpr size_t cap = ( (N-1) > SNMP_MAX_OID_STR_LEN ) ? SNMP_MAX_OID_STR_LEN : (N-1);
        _init_from_cstr(value, cap);
    }

    /* v3.4.2: cloneOID() (shared_ptr form) removed — cloneRaw() is the one
     * clone path, and every former cloneOID() call site now owns its clone
     * directly (zero control blocks). */

    OIDType* cloneRaw() const {
        return asn_new<OIDType>(this->_valueStr, this->data, this->dataLen, this->valid);
    }

    const char* string();
    bool valid = false;

    /* v3.4.0: read-only access to the ENCODED OID bytes (data[0] == 0x2b).
     * Phase 2 zero-copy dispatch matches request OIDs by memcmp on these
     * bytes instead of rendering dotted strings. */
    const uint8_t* encodedData() const { return data; }
    int encodedLen() const { return dataLen; }

    /* v3.4.2: raw-pointer overload — comparing against a raw OIDType must
     * NOT implicitly construct a shared_ptr (control-block heap alloc per
     * comparison, and the temporary's default-delete would target a
     * non-owning pool pointer). */
    bool equals(const OIDType* oid) const {
        return this->dataLen == oid->dataLen &&
               (this->dataLen == 0 || memcmp(this->data, oid->data, (size_t)this->dataLen) == 0);
    }

    bool equals(const OIDType& oid) const {
        return this->equals(&oid);
    }

    bool equals(const std::shared_ptr<OIDType> oid) const {
        return this->equals(oid.get());
    }

    bool isSubTreeOf(const OIDType* const oid){
        if(oid->dataLen >= this->dataLen) return false;
        if(oid->dataLen == 0) return true;
        return memcmp(this->data, oid->data, (size_t)oid->dataLen) == 0;
    }

  protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;

    void _init_from_cstr(const char* value, size_t len) noexcept;
    void _init_from_cstr_with_data(const char* value, size_t len, const uint8_t* srcData, int srcLen, bool valid) noexcept;

    friend class ComplexType;
    template<typename U, typename... Args> friend U* asn_new(Args&&... args);
    OIDType(): BER_CONTAINER(OID) { _valueStr[0] = 0; dataLen = 0; }

    char _valueStr[SNMP_MAX_OID_STR_LEN + 1];
    uint8_t data[SNMP_MAX_OID_SUBIDENTIFIERS + 1];
    int dataLen = 0;

  private:
    explicit OIDType(const char* value, const uint8_t* srcData, int srcLen, bool valid): BER_CONTAINER(OID), valid(valid), dataLen(srcLen) {
        size_t len = strlen(value);
        if(len > SNMP_MAX_OID_STR_LEN) len = SNMP_MAX_OID_STR_LEN;
        _init_from_cstr_with_data(value, len, srcData, srcLen, valid);
    }

    template<size_t N>
    explicit OIDType(const char (&value)[N], const uint8_t* srcData, int srcLen, bool valid): BER_CONTAINER(OID), valid(valid), dataLen(srcLen) {
        constexpr size_t cap = ( (N-1) > SNMP_MAX_OID_STR_LEN ) ? SNMP_MAX_OID_STR_LEN : (N-1);
        _init_from_cstr_with_data(value, cap, srcData, srcLen, valid);
    }

    bool generateInternalData();
};

class SortableOIDType: public OIDType {
  public:
    explicit SortableOIDType(const char* value): OIDType(value) {}

    template<size_t N>
    SortableOIDType(const char (&value)[N]): OIDType(value) {}

    static bool sort_oids(const SortableOIDType* oid1, const SortableOIDType* oid2);

    bool operator < (SortableOIDType& other){
        return SortableOIDType::sort_oids(this, &other);
    }

  private:
};

class NullType: public BER_CONTAINER {
  public:
    NullType(): BER_CONTAINER(NULLTYPE) {}

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;
};

class ImplicitNullType: public NullType {
  public:
    explicit ImplicitNullType(ASN_TYPE type): NullType(){
        //TODO: check that we're one of the implicit null types
        _type = type;
    }
};

class Counter64: public BER_CONTAINER {
  public:
    Counter64(): BER_CONTAINER(COUNTER64) {}
    explicit Counter64(uint64_t value): Counter64(){
        _value = value;
    }

    uint64_t _value = 0;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;
};

class Counter32: public IntegerType {
  public:
    Counter32(): IntegerType(){
        _type = COUNTER32;
    }
    explicit Counter32(unsigned int value): IntegerType(value){
        _type = COUNTER32;
    }

};

class Gauge: public IntegerType { // Unsigned int
  public:
    Gauge(): IntegerType(){
        _type = GAUGE32;
    }
    explicit Gauge(unsigned int value): IntegerType(value){
        _type = GAUGE32;
    }

};

class ComplexType: public BER_CONTAINER {
  public:
    explicit ComplexType(ASN_TYPE type): BER_CONTAINER(type), valuesLen(0), _ownsChildren(false) {}
    ~ComplexType(){
        if(this->_ownsChildren){
            for(int n = 0; n < this->valuesLen; n++){
                asn_delete(this->values[n]);
                this->values[n] = nullptr;
            }
        }
        this->valuesLen = 0;
    }

    BER_CONTAINER* values[SNMP_MAX_COMPLEX_CHILDREN];
    int valuesLen;
    bool _ownsChildren;   /* true = ComplexType owns children (delete in dtor); false = caller owns */

    int fromBuffer(const uint8_t *buf, size_t max_len) override;
    int serialise(uint8_t* buf, size_t max_len) override;

    BER_CONTAINER* addValueToListRaw(BER_CONTAINER* newObj){
        if(!newObj){
            SNMP_LOGE("ComplexType::addValueToListRaw: nullptr child rejected (ASNPool exhausted?)\n");
            return nullptr;
        }
        if(this->valuesLen >= SNMP_MAX_COMPLEX_CHILDREN){
            SNMP_LOGE("ComplexType::addValueToListRaw: values[] full (%d max). Raise SNMP_MAX_COMPLEX_CHILDREN.\n",
                      (int)SNMP_MAX_COMPLEX_CHILDREN);
            return nullptr;
        }
        this->values[this->valuesLen++] = newObj;
        return newObj;
    }

  private:
    static BER_CONTAINER* createObjectForType(ASN_TYPE valueType);
};

/* =====================================================================
 * POOL SLOT RIGHT-SIZE GUARDS
 * ---------------------------------------------------------------------
 * Every concrete BER_CONTAINER subclass that can be placement-new'd into
 * an ASNPool slot MUST appear here. The list is intentionally exhaustive:
 * it is what lets SNMP_POOL_SLOT_SIZE ride the true maximum (288/312)
 * instead of stale headroom — an oversized slot pads the arena's objects
 * with dead bytes and wastes scarce RAM on constrained targets.
 * If you add or grow a container type, the matching assert below fires
 * at compile time: raise SNMP_POOL_SLOT_SIZE (sketch-side #define wins)
 * AND add the type here. No silent runtime placement failures.
 * ===================================================================== */
static_assert(sizeof(OctetType)       <= SNMP_POOL_SLOT_SIZE, "OctetType exceeds ASNPool slot size — raise SNMP_POOL_SLOT_SIZE (see guard comment at end of BER.h)");
static_assert(sizeof(OpaqueType)      <= SNMP_POOL_SLOT_SIZE, "OpaqueType exceeds ASNPool slot size — raise SNMP_POOL_SLOT_SIZE (see guard comment at end of BER.h)");
static_assert(sizeof(SortableOIDType) <= SNMP_POOL_SLOT_SIZE, "SortableOIDType exceeds ASNPool slot size — raise SNMP_POOL_SLOT_SIZE (see guard comment at end of BER.h)");
static_assert(sizeof(OIDType)         <= SNMP_POOL_SLOT_SIZE, "OIDType exceeds ASNPool slot size — raise SNMP_POOL_SLOT_SIZE (see guard comment at end of BER.h)");
static_assert(sizeof(ComplexType)     <= SNMP_POOL_SLOT_SIZE, "ComplexType exceeds ASNPool slot size — raise SNMP_POOL_SLOT_SIZE (see guard comment at end of BER.h)");
static_assert(sizeof(NetworkAddress)  <= SNMP_POOL_SLOT_SIZE, "NetworkAddress exceeds ASNPool slot size");
static_assert(sizeof(Counter64)       <= SNMP_POOL_SLOT_SIZE, "Counter64 exceeds ASNPool slot size");

#endif
