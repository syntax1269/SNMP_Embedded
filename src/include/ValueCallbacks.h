#ifndef VALUE_CALLBACKS_h
#define VALUE_CALLBACKS_h

#include "BER.h"
#include "BERView.h"
#include <algorithm>

/* v3.4.2: the zero-heap factory alias.  Every library callback builds its
 * response value through asn_new<T>() into the pool; AsnPtr (move-only,
 * destructor -> asn_delete) carries it to the response plan with zero heap
 * traffic.  Replaces the former vcb_pool_shared() shared_ptr helper whose
 * control block was a per-value heap allocation (Report_001 finding #1). */
template <typename T>
static inline AsnPtr<BER_CONTAINER> vcb_pool_ptr(T* p) noexcept {
    return AsnPtr<BER_CONTAINER>(p);
}

typedef int (*GETINT_FUNC)() ;
typedef uint32_t (*GETUINT_FUNC)();
typedef const char* (*GETSTRING_FUNC)();

class ValueCallback {
  public:
    ValueCallback(SortableOIDType* oid, ASN_TYPE type): OID(oid), type(type){}
    virtual ~ValueCallback(){
        asn_delete(OID);
    }
    SortableOIDType * const OID;

    ASN_TYPE type;

    bool isSettable = false;
    bool setOccurred = false;

    void resetSetOccurred(){
        setOccurred = false;
    }

    static const char* getTypeName(ASN_TYPE t) noexcept;
    virtual const char* getAccessTag() const noexcept { return isSettable ? "RW" : "RO"; }

    static ValueCallback* findCallback(ValueCallback* const *callbacks, int callbacksCount, const OIDType* const oid, bool walk, int startAt = 0, int *foundAt = nullptr);
#if SNMP_ZERO_COPY
    /* v3.4.0 Phase 2 — dispatch on the raw encoded-OID slice (zero-copy).
     * Exact contract twin of findCallback(): same walk semantics (exact
     * match, or next-in-sorted-order; subtree catch for walk start points),
     * same sorted-roster preconditions — but compares against the request's
     * wire bytes directly.  Matching never copies, renders, or allocates.
     * Returns nullptr when no handler matches (caller emits noSuchObject /
     * endOfMibview exactly as today). */
    static ValueCallback* findCallbackForSlice(ValueCallback* const *callbacks, int callbacksCount,
                                               const uint8_t* oidData, int oidLen, bool walk,
                                               int startAt = 0, int *foundAt = nullptr);
#endif /* SNMP_ZERO_COPY */
    /* v3.4.2 — zero-heap value path.  getValueForCallback() now returns a
     * move-only AsnPtr (pool-owned, destructor -> asn_delete, no heap
     * bookkeeping).  setValueForCallback() takes a BORROWED const view:
     * the value is only read during the call, never retained. */
    static AsnPtr<BER_CONTAINER> getValueForCallback(ValueCallback* callback);
    static SNMP_ERROR_STATUS setValueForCallback(ValueCallback* callback, const BER_CONTAINER* value);

protected:
    /* v3.4.2 — the factory every library callback overrides.  Returns a
     * pool-owning AsnPtr; empty on pool exhaustion or an invalid source
     * value (mirrors the old nullptr return). */
    virtual AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() = 0;

    /* DEPRECATED legacy factory (shared_ptr era).  Nothing in this library
     * or its examples overrides it any more; kept ONLY so external sketches
     * written against the pre-3.4.2 header still compile and run.  An
     * external override pays one shared_ptr control block per GET — the
     * exact cost this release removes from the library's own path.
     * Default: empty (an external subclass that overrides NEITHER factory
     * serves no value; pre-3.4.2 the pure virtual forced an override, so
     * this default is unreachable for any real legacy subclass).
     * Removal: next major. */
    virtual std::shared_ptr<BER_CONTAINER> buildTypeWithValue() { return nullptr; }

    virtual SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) = 0;
};

bool compare_callbacks (const ValueCallback* first, const ValueCallback* second);
void sort_handlers(ValueCallback** callbacks, int callbacksCount);
bool remove_handler(ValueCallback** callbacks, int& callbacksCount, ValueCallback*);

class IntegerCallback: public ValueCallback {
  public:
    IntegerCallback(SortableOIDType* oid, int* value): ValueCallback(oid, INTEGER), value(value) {}

  protected:
    int* const value;
    int modifier = 0;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class StaticIntegerCallback: public ValueCallback {
  public:
    StaticIntegerCallback(SortableOIDType* oid, int value): ValueCallback(oid, INTEGER), val(value) {}

  protected:
    const int val;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override {
        return vcb_pool_ptr(asn_new<IntegerType>(val));
    }

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    }
};

class DynamicIntegerCallback: public ValueCallback {
public:
    DynamicIntegerCallback(SortableOIDType* oid, GETINT_FUNC callback_func):
        ValueCallback(oid, INTEGER), m_callback(callback_func) {}
    const char* getAccessTag() const noexcept override { return "DYN"; }

protected:
    GETINT_FUNC m_callback;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override {
        return vcb_pool_ptr(asn_new<IntegerType>(m_callback()));
    }

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    }
};

class TimestampCallback: public ValueCallback {
  public:
    TimestampCallback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, TIMESTAMP), value(value) {}

  protected:
    uint32_t* const value;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class DynamicTimestampCallback: public ValueCallback {
public:
    DynamicTimestampCallback(SortableOIDType* oid, GETUINT_FUNC callback_func):
    ValueCallback(oid, TIMESTAMP), m_callback(callback_func) {}
    const char* getAccessTag() const noexcept override { return "DYN"; }

protected:
    GETUINT_FUNC m_callback;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override {
        return vcb_pool_ptr(asn_new<TimestampType>(m_callback()));
    }

    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    }
};

class ReadOnlyStringCallback: public ValueCallback {
public:
    ReadOnlyStringCallback(SortableOIDType* oid, const char *value): ValueCallback(oid, STRING) {
        size_t len = strlen(value);
        if(len > SNMP_MAX_STRING_LEN) len = SNMP_MAX_STRING_LEN;
        memcpy(this->value, value, len);
        this->value[len] = 0;
    }

protected:
    char value[SNMP_MAX_STRING_LEN + 1];

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    }
};

class DynamicStringCallback: public ValueCallback {
public:
    DynamicStringCallback(SortableOIDType* oid, GETSTRING_FUNC callback): ValueCallback(oid, STRING), m_callback(callback) {}
    const char* getAccessTag() const noexcept override { return "DYN"; }

protected:
    GETSTRING_FUNC m_callback;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override {
      return vcb_pool_ptr(asn_new<OctetType>(m_callback()));
    }
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER*) override {
        return NO_ACCESS;
    }
};

class StringCallback: public ValueCallback {
  public:
    StringCallback(SortableOIDType* oid, char** value, size_t max_len): ValueCallback(oid, STRING), value(value), max_len(max_len) {}

  protected:
    char** const value;
    size_t const max_len;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

/* v3.3.5: array-backed RW string — binds the char[] buffer DIRECTLY (no char*
 * pointer variable needed), so addRFC1213SystemGroup's auto-size form can serve
 * "pass the array, the library sizes it" with zero user sizeof() trivia.
 * Semantics identical to StringCallback: GET serves *the buffer contents,
 * SET strncpy's into it, bounded by max_len (the deduced array capacity). */
class StringBufCallback: public ValueCallback {
  public:
    StringBufCallback(SortableOIDType* oid, char* value, size_t max_len): ValueCallback(oid, STRING), value(value), max_len(max_len) {}

  protected:
    char* const  value;
    size_t const max_len;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class OpaqueCallback: public ValueCallback {
  public:
    OpaqueCallback(SortableOIDType* oid, uint8_t* value, int data_len): ValueCallback(oid, OPAQUE), value(value), data_len(data_len) {}

  protected:
    uint8_t* const value;
    int const data_len;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class OIDCallback: public ValueCallback {
  public:
    OIDCallback(SortableOIDType* oid, const char *value): ValueCallback(oid, ASN_TYPE::OID) {
        size_t len = strlen(value);
        if(len > SNMP_MAX_OID_STR_LEN) len = SNMP_MAX_OID_STR_LEN;
        memcpy(this->value, value, len);
        this->value[len] = 0;
    }

  protected:
    char value[SNMP_MAX_OID_STR_LEN + 1];

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue (BER_CONTAINER*) override{
        return NO_ACCESS;
    }
};

class Counter32Callback: public ValueCallback {
  public:
    Counter32Callback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, COUNTER32), value(value) {}

  protected:
    uint32_t* const value;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};


class Gauge32Callback: public ValueCallback {
  public:
    Gauge32Callback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, GAUGE32), value(value) {}

  protected:
    uint32_t* const value;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class DynamicGauge32Callback: public ValueCallback {
  public:
    DynamicGauge32Callback(SortableOIDType* oid, GETUINT_FUNC callback_func): ValueCallback(oid, GAUGE32), m_callback(callback_func) {}
    const char* getAccessTag() const noexcept override { return "DYN"; }

  protected:
    GETUINT_FUNC m_callback;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override {
        return vcb_pool_ptr(asn_new<Gauge>(m_callback()));
    }
    SNMP_ERROR_STATUS setTypeWithValue (BER_CONTAINER*) override{
        return NO_ACCESS;
    }
};

class Counter64Callback: public ValueCallback {
  public:
    Counter64Callback(SortableOIDType* oid, uint64_t* value): ValueCallback(oid, COUNTER64), value(value) {}

  protected:
    uint64_t* const value;

    AsnPtr<BER_CONTAINER> buildTypeWithValueRaw() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

#endif
