#ifndef SNMPPacket_h
#define SNMPPacket_h

#include "VarBinds.h"
#include "defs.h"
#include <math.h>
#include <utility>

enum SNMPParsingState {
    SNMPVERSION,
    COMMUNITY,
    PDU,
    REQUESTID,
    ERRORSTATUS,
    ERRORID,
    VARBINDS,
    VARBIND,
    DONE
};

typedef int SNMP_PACKET_PARSE_ERROR;

#define SNMP_PARSE_ERROR_MAGIC_BYTE -2 + SNMP_PACKET_PARSE_ERROR_OFFSET
#define SNMP_PARSE_ERROR_GENERIC -1 + SNMP_PACKET_PARSE_ERROR_OFFSET


union ErrorStatus {
  SNMP_ERROR_STATUS errorStatus;
  int nonRepeaters;
};

union ErrorIndex {
  int errorIndex;
  int maxRepititions;
};

class SNMPPacket {
  public:
    SNMPPacket(){}
    explicit SNMPPacket(const SNMPPacket& packet){
        this->setRequestID(packet.requestID);
        this->setVersion(packet.snmpVersion);
        this->setCommunityString(packet.communityString);

        // Provide reusable ASN containers if required
        if(packet.requestIDPtr){
            this->requestIDPtr = packet.requestIDPtr;
        }

        if(packet.snmpVersionPtr){
            this->snmpVersionPtr = packet.snmpVersionPtr;
        }

        if(packet.communityStringPtr){
            this->communityStringPtr = packet.communityStringPtr;
        }

        /* NOTE: varbindCount / varbindList[] are intentionally NOT copied.
         * The new object starts with an empty varbind list (in-class
         * initializers: varbindCount=0 + default-constructed VarBind
         * slots) because callers (e.g. SNMPResponse copy-from-request)
         * populate the response via addResponse() calls. */
    }

    virtual ~SNMPPacket();

    static snmp_request_id_t generate_request_id();
    
    SNMP_PACKET_PARSE_ERROR parseFrom(uint8_t* buf, size_t max_len);
    int serialiseInto(uint8_t* buf, size_t max_len);

    //TODO: put checks in all these setters
    void setCommunityString(const char *CommunityString);
    void setRequestID(snmp_request_id_t);
    bool setPDUType(ASN_TYPE);
    void setVersion(SNMP_VERSION);

    bool reuse = false;

    std::shared_ptr<IntegerType> requestIDPtr = nullptr;
    std::shared_ptr<IntegerType> snmpVersionPtr = nullptr;
    std::shared_ptr<OctetType> communityStringPtr = nullptr;

    snmp_request_id_t requestID = 0;
    SNMP_VERSION snmpVersion = (SNMP_VERSION)0;
    char communityString[SNMP_MAX_COMMUNITY_LEN + 1] = {0};

    ASN_TYPE packetPDUType;

    /* ----- fixed-capacity varbind list ----- */
    VarBind varbindList[SNMP_MAX_VARBINDS];
    int varbindCount = 0;

    int size() const { return this->varbindCount; }

    VarBind& at(int idx){ return this->varbindList[idx]; }
    const VarBind& at(int idx) const { return this->varbindList[idx]; }

    VarBind& operator[](int idx){ return this->varbindList[idx]; }
    const VarBind& operator[](int idx) const { return this->varbindList[idx]; }

    VarBind* begin(){ return &this->varbindList[0]; }
    VarBind* end(){ return &this->varbindList[0] + this->varbindCount; }
    const VarBind* begin() const { return &this->varbindList[0]; }
    const VarBind* end()   const { return &this->varbindList[0] + this->varbindCount; }

    /* True if appended. False on capacity overflow (caller should signal error). */
    template<typename... Args>
    bool emplace_back(Args&&... args){
        if(this->varbindCount >= SNMP_MAX_VARBINDS) return false;
        /* Placement-new into the pre-allocated array slot.  Destroy first
         * if slot had a previous object (from re-use before clear).  This
         * is safe because VarBind has non-trivial dtor that frees oid/value. */
        this->varbindList[this->varbindCount].~VarBind();
        new (&this->varbindList[this->varbindCount]) VarBind(std::forward<Args>(args)...);
        this->varbindCount++;
        return true;
    }

    bool push_back(const VarBind& vb){
        if(this->varbindCount >= SNMP_MAX_VARBINDS) return false;
        this->varbindList[this->varbindCount].~VarBind();
        new (&this->varbindList[this->varbindCount]) VarBind(vb);
        this->varbindCount++;
        return true;
    }

    void pop_back(){
        if(this->varbindCount > 0){
            this->varbindCount--;
            /* Destroy the element we just popped (frees owned oid/value).
             * Then reconstruct a valid default VarBind so the slot is safe
             * when the enclosing array is destroyed. */
            this->varbindList[this->varbindCount].~VarBind();
            new (&this->varbindList[this->varbindCount]) VarBind();
        }
    }

    void clear(){
        while(this->varbindCount > 0){
            this->varbindCount--;
            this->varbindList[this->varbindCount].~VarBind();
            new (&this->varbindList[this->varbindCount]) VarBind();
        }
    }

    /* v3.3.3 — stateless teardown of all pool-backed members (packet tree,
     * varbindList contents, parsed header containers).  Traps/informs are
     * persistent sketch objects whose members previously outlived the send:
     * ASNPool::resetAll() in loop() flag-freed those slots while the pointers
     * remained live, and after flood traffic recycled them the NEXT trap's
     * stale deletes/cloans hit re-armed slots — the residual "slot-12" DOUBLE
     * RELEASE alarm (and a latent use-after-reuse).  Releasing immediately
     * after serialisation leaves nothing stale: the next rebuild's
     * asn_delete(this->packet) is asn_delete(nullptr).  Idempotent. */
    virtual void releasePoolState(){        this->clear();                       /* frees varbindList oid/value  */
        asn_delete(this->packet);            /* frees the whole packet tree  */
        this->packet = nullptr;
        this->requestIDPtr      = nullptr;   /* parsed-header containers     */
        this->snmpVersionPtr    = nullptr;
        this->communityStringPtr = nullptr;
    }

    union ErrorStatus errorStatus = { NO_ERROR };
    union ErrorIndex errorIndex = {0};

    ComplexType* packet = nullptr;
    
  protected:
    virtual bool build();

    typedef bool (*BuildPDUHeaderFn)(ComplexType* snmpPDU, void* userdata);

    bool _build_pdu_envelope(BuildPDUHeaderFn fill_pdu, void* userdata);

    virtual std::shared_ptr<ComplexType> generateVarBindList();

    /* Build the varbind tree with uniform recursive ownership (raw new'd;
     * every ComplexType node has _ownsChildren=true).  Used by build()
     * directly to avoid shared_ptr ownership-transfer difficulties. */
    virtual ComplexType* generateVarBindListRaw();

  private:
    SNMP_PACKET_PARSE_ERROR parsePacket(ComplexType* structure, enum SNMPParsingState state);
};


#endif
