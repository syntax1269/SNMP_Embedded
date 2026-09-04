#ifndef VALUE_CALLBACKS_h
#define VALUE_CALLBACKS_h

#include "BER.h"
#include <algorithm>

template <typename T>
static inline void vcb_pool_asn_deleter(T* p) noexcept {
    asn_delete(static_cast<BER_CONTAINER*>(p));
}

template <typename T>
static inline std::shared_ptr<T> vcb_pool_shared(T* p) noexcept {
    if(!p) return nullptr;
    return std::shared_ptr<T>(p, vcb_pool_asn_deleter<T>);
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
    static std::shared_ptr<BER_CONTAINER> getValueForCallback(ValueCallback* callback);
    static SNMP_ERROR_STATUS setValueForCallback(ValueCallback* callback, const std::shared_ptr<BER_CONTAINER> &value);

protected:
    virtual std::shared_ptr<BER_CONTAINER> buildTypeWithValue() = 0;
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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class StaticIntegerCallback: public ValueCallback {
  public:
    StaticIntegerCallback(SortableOIDType* oid, int value): ValueCallback(oid, INTEGER), val(value) {}

  protected:
    const int val;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
        return vcb_pool_shared(asn_new<IntegerType>(val));
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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
        return vcb_pool_shared(asn_new<IntegerType>(m_callback()));
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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class DynamicTimestampCallback: public ValueCallback {
public:
    DynamicTimestampCallback(SortableOIDType* oid, GETUINT_FUNC callback_func):
    ValueCallback(oid, TIMESTAMP), m_callback(callback_func) {}
    const char* getAccessTag() const noexcept override { return "DYN"; }

protected:
    GETUINT_FUNC m_callback;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
        return vcb_pool_shared(asn_new<TimestampType>(m_callback()));
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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
      return vcb_pool_shared(asn_new<OctetType>(m_callback()));
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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class OpaqueCallback: public ValueCallback {
  public:
    OpaqueCallback(SortableOIDType* oid, uint8_t* value, int data_len): ValueCallback(oid, OPAQUE), value(value), data_len(data_len) {}

  protected:
    uint8_t* const value;
    int const data_len;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue (BER_CONTAINER*) override{
        return NO_ACCESS;
    }
};

class Counter32Callback: public ValueCallback {
  public:
    Counter32Callback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, COUNTER32), value(value) {}

  protected:
    uint32_t* const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};


class Gauge32Callback: public ValueCallback {
  public:
    Gauge32Callback(SortableOIDType* oid, uint32_t* value): ValueCallback(oid, GAUGE32), value(value) {}

  protected:
    uint32_t* const value;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

class DynamicGauge32Callback: public ValueCallback {
  public:
    DynamicGauge32Callback(SortableOIDType* oid, GETUINT_FUNC callback_func): ValueCallback(oid, GAUGE32), m_callback(callback_func) {}
    const char* getAccessTag() const noexcept override { return "DYN"; }

  protected:
    GETUINT_FUNC m_callback;

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override {
        return vcb_pool_shared(asn_new<Gauge>(m_callback()));
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

    std::shared_ptr<BER_CONTAINER> buildTypeWithValue() override;
    SNMP_ERROR_STATUS setTypeWithValue(BER_CONTAINER* value) override;
};

#endif
