#ifndef VarBinds_h
#define VarBinds_h

#include "BER.h"
#include "ValueCallbacks.h"

#include <memory>

class VarBind {
  public:
    /* ----- constructors ----- */

    /* Default ctor: builds a VarBind with no OID/value.  Needed so that
     * fixed arrays (VarBind arr[N]) can be member-declared and have the
     * compiler auto-destroy each slot safely (destroy on nullptr is OK). */
    VarBind():
        oid(nullptr),
        type(NULLTYPE),
        value(nullptr),
        errorStatus(NO_ERROR) {}

    /* Owns both oid and value (takes ownership of the raw pointers). */
    VarBind(OIDType* oid_, BER_CONTAINER* value_):
        oid(oid_),
        type(value_ ? value_->_type : NULLTYPE),
        value(value_),
        errorStatus(NO_ERROR) {}

    /* Convenience: constructs a NullType value for error reporting.
     * Takes ownership of oid_. */
    VarBind(OIDType* oid_, SNMP_ERROR_STATUS error):
        oid(oid_),
        type(NULLTYPE),
        value(asn_new<NullType>()),
        errorStatus(error) {}

    /* Ctor that takes const SortableOIDType* (classic public API).
     * Clones the OID (cloneRaw -> new owned copy). Takes ownership of
     * value_ (raw, transferred). */
    VarBind(const SortableOIDType* oidSrc, BER_CONTAINER* value_):
        oid(oidSrc->cloneRaw()),
        type(value_ ? value_->_type : NULLTYPE),
        value(value_),
        errorStatus(NO_ERROR) {}

    /* Ctor that takes const SortableOIDType* + error status.
     * Clones the OID; allocates new NullType value. */
    VarBind(const SortableOIDType* oidSrc, SNMP_ERROR_STATUS error):
        oid(oidSrc->cloneRaw()),
        type(NULLTYPE),
        value(asn_new<NullType>()),
        errorStatus(error) {}

    /* v3.4.2: MOVE-OWNERSHIP ctor — takes the value's pool object directly
     * (AsnPtr::release), no clone.  This is the hot-path ctor: GET/SET/
     * GETBULK response values flow through here with zero heap traffic.
     * (The former shared_ptr overload deep-cloned the value AND cost a
     * control block; both costs are gone.) */
    VarBind(OIDType* oid_, AsnPtr<BER_CONTAINER> valueSP):
        oid(oid_),
        type(valueSP ? valueSP->_type : NULLTYPE),
        value(valueSP ? valueSP.release() : asn_new<NullType>()),
        errorStatus(NO_ERROR) {}

    /* Legacy convenience ctor kept for API compatibility: deep-clones any
     * shared_ptr value content into owned raw storage (shared_ptr is never
     * stored).  Used by sketches/tests still handing shared_ptr values. */
    VarBind(OIDType* oid_, const std::shared_ptr<BER_CONTAINER>& valueSP):
        oid(oid_),
        type(valueSP ? valueSP->_type : NULLTYPE),
        value(cloneValueOrNull(valueSP.get(), valueSP ? valueSP->_type : NULLTYPE)),
        errorStatus(NO_ERROR) {}

    /* Copy ctor: deep-clones both oid and value so each VarBind owns
     * independent storage. Used pervasively by std::deque<VarBind>. */
    VarBind(const VarBind& other):
        oid(cloneOidOrNull(other.oid)),
        type(other.type),
        value(cloneValueOrNull(other.value, other.type)),
        errorStatus(other.errorStatus) {}

    /* Copy-assignment: deep-clone, free old resources, assign new. */
    VarBind& operator=(const VarBind& other){
        if(this != &other){
            destroy();
            oid         = cloneOidOrNull(other.oid);
            type        = other.type;
            value       = cloneValueOrNull(other.value, other.type);
            errorStatus = other.errorStatus;
        }
        return *this;
    }

    /* Legacy ctors kept for API / test compatibility.  They extract raw
     * pointers from shared_ptr and clone everything into owned raw
     * storage.  Shared_ptrs are not stored at all. */

    VarBind(const std::shared_ptr<OIDType>& oidSP, const std::shared_ptr<BER_CONTAINER>& valueSP):
        oid(cloneOidOrNull(oidSP.get())),
        type(valueSP ? valueSP->_type : NULLTYPE),
        value(cloneValueOrNull(valueSP.get(), valueSP ? valueSP->_type : NULLTYPE)),
        errorStatus(NO_ERROR) {}

    VarBind(const std::shared_ptr<OIDType>& oidSP, SNMP_ERROR_STATUS error):
        oid(cloneOidOrNull(oidSP.get())),
        type(NULLTYPE),
        value(asn_new<NullType>()),
        errorStatus(error) {}

    VarBind(const SortableOIDType* oidSrc, const std::shared_ptr<BER_CONTAINER>& valueSP):
        oid(oidSrc->cloneRaw()),
        type(valueSP ? valueSP->_type : NULLTYPE),
        value(cloneValueOrNull(valueSP.get(), valueSP ? valueSP->_type : NULLTYPE)),
        errorStatus(NO_ERROR) {}

    /* v3.4.2: move-ownership twin (classic-path GET results). */
    VarBind(const SortableOIDType* oidSrc, AsnPtr<BER_CONTAINER> valueSP):
        oid(oidSrc->cloneRaw()),
        type(valueSP ? valueSP->_type : NULLTYPE),
        value(valueSP ? valueSP.release() : asn_new<NullType>()),
        errorStatus(NO_ERROR) {}

    /* "Replace value" ctors: copies OID and type from existing VarBind,
     * installs a new owned value.  Used in PDU handlers for endOfMibView
     * / noSuchObject / normal get-result responses.  Both raw and
     * shared_ptr forms provided. */
    VarBind(const VarBind& vb, BER_CONTAINER* value_):
        oid(cloneOidOrNull(vb.oid)),
        type(value_ ? value_->_type : vb.type),
        value(value_ ? value_ : asn_new<NullType>()),
        errorStatus(vb.errorStatus) {}

    VarBind(const VarBind& vb, const std::shared_ptr<BER_CONTAINER>& valueSP):
        oid(cloneOidOrNull(vb.oid)),
        type(valueSP ? valueSP->_type : vb.type),
        value(cloneValueOrNull(valueSP.get(), valueSP ? valueSP->_type : NULLTYPE)),
        errorStatus(vb.errorStatus) {}

    /* v3.4.2: move-ownership "replace value" twin. */
    VarBind(const VarBind& vb, AsnPtr<BER_CONTAINER> valueSP):
        oid(cloneOidOrNull(vb.oid)),
        type(valueSP ? valueSP->_type : vb.type),
        value(valueSP ? valueSP.release() : asn_new<NullType>()),
        errorStatus(vb.errorStatus) {}

    /* Destructor: frees owned oid + value. */
    ~VarBind(){ destroy(); }

    /* ----- members (non-const: assignments supported) ----- */
    OIDType* oid;
    ASN_TYPE type;
    BER_CONTAINER* value;
    SNMP_ERROR_STATUS errorStatus = NO_ERROR;

    /* v3.4.2: public — SNMPPacket::parsePacket uses it to deep-clone parsed
     * varbind values into owned raw storage (replaces the shared_ptr view). */
    static BER_CONTAINER* cloneValueOrNull(const BER_CONTAINER* src, ASN_TYPE fallbackType){
        if(!src){
            switch(fallbackType){
                case NULLTYPE:       return asn_new<NullType>();
                case NOSUCHOBJECT:   return asn_new<ImplicitNullType>(NOSUCHOBJECT);
                case NOSUCHINSTANCE: return asn_new<ImplicitNullType>(NOSUCHINSTANCE);
                case ENDOFMIBVIEW:   return asn_new<ImplicitNullType>(ENDOFMIBVIEW);
                default:             return asn_new<NullType>();
            }
        }
        switch(src->_type){
            case INTEGER:        return asn_new<IntegerType>(static_cast<const IntegerType*>(src)->_value);
            case STRING:
            {
                const OctetType* so = static_cast<const OctetType*>(src);
                return asn_new<OctetType>(so->_value, so->_valueLen);
            }
            case OID:            return static_cast<const OIDType*>(src)->cloneRaw();
            case NULLTYPE:       return asn_new<NullType>();
            case NOSUCHOBJECT:   return asn_new<ImplicitNullType>(NOSUCHOBJECT);
            case NOSUCHINSTANCE: return asn_new<ImplicitNullType>(NOSUCHINSTANCE);
            case ENDOFMIBVIEW:   return asn_new<ImplicitNullType>(ENDOFMIBVIEW);
            case NETWORK_ADDRESS:
            {
                const NetworkAddress* so = static_cast<const NetworkAddress*>(src);
                return asn_new<NetworkAddress>(so->_value);
            }
            case TIMESTAMP:      return asn_new<TimestampType>(static_cast<const TimestampType*>(src)->_value);
            case COUNTER32:      return asn_new<Counter32>(static_cast<const Counter32*>(src)->_value);
            case GAUGE32:        return asn_new<Gauge>(static_cast<const Gauge*>(src)->_value);
            case COUNTER64:      return asn_new<Counter64>(static_cast<const Counter64*>(src)->_value);
            case OPAQUE:
            {
                const OpaqueType* so = static_cast<const OpaqueType*>(src);
                return asn_new<OpaqueType>(so->_value, so->_dataLength);
            }
            default:             return asn_new<NullType>();
        }
    }

  private:
    void destroy(){
        asn_delete(this->oid);   this->oid   = nullptr;
        asn_delete(this->value); this->value = nullptr;
    }

    static OIDType* cloneOidOrNull(const OIDType* src){
        return src ? src->cloneRaw() : nullptr;
    }
};

#endif
