#include "include/SNMPPacket.h"

#define SNMP_PARSE_ERROR_AT_STATE(STATE) ((int)STATE * -1) - 10 + SNMP_PACKET_PARSE_ERROR_OFFSET

/* v3.4.2: pool_shared/pool_asn_deleter removed — the packet hot path is
 * fully AsnPtr-based (zero heap).  The former shared_ptr wrappers each
 * cost a heap control block per construction (Report_001 finding #1). */

#define ASN_TYPE_FOR_STATE_SNMPVERSION  INTEGER
#define ASN_TYPE_FOR_STATE_COMMUNITY    STRING
#define ASN_TYPE_FOR_STATE_REQUESTID    INTEGER
#define ASN_TYPE_FOR_STATE_ERRORSTATUS  INTEGER
#define ASN_TYPE_FOR_STATE_ERRORID      INTEGER
#define ASN_TYPE_FOR_STATE_VARBINDS     STRUCTURE
#define ASN_TYPE_FOR_STATE_VARBIND      STRUCTURE

#define STR_IMPL_(x) #x      //stringify argument
#define STR(x) STR_IMPL_(x)  //indirection to expand argument macros

#define ASSERT_ASN_TYPE_AT_STATE(value, TYPE, STATE) \
    if(!value || value->_type != TYPE) { \
        SNMP_LOGW("Expecting value to be " STR(TYPE) " for " #STATE); \
        return SNMP_PARSE_ERROR_GENERIC; \
    }

#define ASSERT_ASN_STATE_TYPE(value, STATE) \
    if(!value || value->_type != ASN_TYPE_FOR_STATE_##STATE) { \
        SNMP_LOGW("Expecting " STR(ASN_TYPE_FOR_STATE_##STATE) " for " #STATE " failed: %d\n", value->_type); \
        return SNMP_PARSE_ERROR_AT_STATE(STATE); \
    }

#define ASSERT_ASN_PARSING_TYPE_RANGE(value, LOW_TYPE, HIGH_TYPE) \
    if(!value || !(value->_type >= LOW_TYPE && value->_type <= HIGH_TYPE)){ \
        SNMP_LOGW("Expecting vartype for PDU failed: %d\n", value->_type); \
        return SNMP_PARSE_ERROR_GENERIC; \
    }

SNMPPacket::~SNMPPacket(){
    asn_delete(this->packet);
}

SNMP_PACKET_PARSE_ERROR SNMPPacket::parsePacket(ComplexType *structure, enum SNMPParsingState state) {
    for(int n = 0; n < structure->valuesLen && state != DONE; n++){
        BER_CONTAINER* value = structure->values[n];

        switch(state) {

            case SNMPVERSION:
                ASSERT_ASN_STATE_TYPE(value, SNMPVERSION);
                {
                /* v3.4.3 (fuzz finding F2): validate the raw integer BEFORE
                 * casting — a hostile version field (e.g. 0xFFFFFFFF) made
                 * the enum cast itself undefined behaviour. */
                int parsedVersion = static_cast<IntegerType*>(value)->_value;
                if(parsedVersion < 0 || parsedVersion >= SNMP_VERSION_MAX){
                    SNMP_LOGW("Invalid SNMP Version: %d\n", parsedVersion);
                    return SNMP_PARSE_ERROR_AT_STATE(SNMPVERSION);
                }
                this->snmpVersionPtr = AsnPtr<IntegerType>(asn_new<IntegerType>(parsedVersion));
                this->snmpVersion = (SNMP_VERSION) parsedVersion;
                }
                state = COMMUNITY;
            break;

            case COMMUNITY:
                ASSERT_ASN_STATE_TYPE(value, COMMUNITY);
                {
                    OctetType* src = static_cast<OctetType*>(value);
                    this->communityStringPtr = AsnPtr<OctetType>(asn_new<OctetType>(src->_value, src->_valueLen));
                }
                {
                    size_t len = this->communityStringPtr.get()->_valueLen;
                    if(len > SNMP_MAX_COMMUNITY_LEN){
                        SNMP_LOGW("parse COMMUNITY: incoming length %zu > SNMP_MAX_COMMUNITY_LEN=%d → reject (no truncation).  Raise cap via #define SNMP_MAX_COMMUNITY_LEN N BEFORE including SNMP_Embedded.h if needed.\n",
                                  len, (int)SNMP_MAX_COMMUNITY_LEN);
                        this->communityString[0] = 0;
                    } else {
                        memcpy(this->communityString, this->communityStringPtr.get()->_value, len);
                        this->communityString[len] = 0;
                    }
                }
                state = PDU;
            break;

            case PDU:
                ASSERT_ASN_PARSING_TYPE_RANGE(value, ASN_PDU_TYPE_MIN_VALUE, ASN_PDU_TYPE_MAX_VALUE)
                this->packetPDUType = value->_type;
                return this->parsePacket(static_cast<ComplexType*>(value), REQUESTID);

            case REQUESTID:
                ASSERT_ASN_STATE_TYPE(value, REQUESTID);
                this->requestIDPtr = AsnPtr<IntegerType>(asn_new<IntegerType>(static_cast<IntegerType*>(value)->_value));
                this->requestID = this->requestIDPtr.get()->_value;
                state = ERRORSTATUS;
            break;

            case ERRORSTATUS:
                ASSERT_ASN_STATE_TYPE(value, ERRORSTATUS);
                this->errorStatus.errorStatus = (SNMP_ERROR_STATUS) static_cast<IntegerType *>(value)->_value;
                state = ERRORID;
            break;

            case ERRORID:
                ASSERT_ASN_STATE_TYPE(value, ERRORID);
                this->errorIndex.errorIndex = static_cast<IntegerType*>(value)->_value;
                state = VARBINDS;
            break;

            case VARBINDS:
                ASSERT_ASN_STATE_TYPE(value, VARBINDS);
                // we have a varbind structure, lets dive into it.
                return this->parsePacket(static_cast<ComplexType*>(value), VARBIND);

            case VARBIND:
            {
                ASSERT_ASN_STATE_TYPE(value, VARBIND);
                // we are in a single varbind

                ComplexType* varbindValues = static_cast<ComplexType*>(value);

                if (varbindValues->valuesLen != 2) {
                    SNMP_LOGW("Expecting VARBIND TO CONTAIN 2 OBEJCTS; %d\n",
                              varbindValues ? varbindValues->valuesLen : 0);
                    return SNMP_PARSE_ERROR_AT_STATE(VARBIND);
                };

                BER_CONTAINER* vbOid = varbindValues->values[0];
                ASSERT_ASN_TYPE_AT_STATE(vbOid, OID, VARBIND);

                BER_CONTAINER* vbValue = varbindValues->values[1];

                /* v3.4.2: raw pool clones — the VarBind owns both members
                 * outright (no shared_ptr view, no control blocks).  The
                 * incoming ComplexType tree outlives the emplaced VarBind
                 * within parsePacket's scope, and the VarBind's own deep
                 * copies are independent of it after construction. */
                OIDType* oidClone = static_cast<OIDType*>(vbOid)->cloneRaw();
                BER_CONTAINER* valueClone = VarBind::cloneValueOrNull(vbValue, vbValue ? vbValue->_type : NULLTYPE);

                /* LOUD REJECT on capacity overflow. The former behavior
                 * silently dropped varbinds past SNMP_MAX_VARBINDS, so a
                 * request with more varbinds than the compile-time cap was
                 * processed as a truncated request with no diagnostic.
                 * New behavior: fail the parse with an explicit error code
                 * (handlePacket() maps it to SNMP_REQUEST_INVALID — no
                 * response). Mirrors the community-cap policy:
                 * truncation replaced with explicit reject. */
                if(!this->emplace_back(oidClone, valueClone)){
                    SNMP_LOGW("Request varbind #%d exceeds SNMP_MAX_VARBINDS (%d): REJECTING packet (was: silently truncated). Raise SNMP_MAX_VARBINDS via sketch #define before #include <SNMP_Embedded.h>.\n",
                              this->varbindCount + 1, SNMP_MAX_VARBINDS);
                    return SNMP_PARSE_ERROR_AT_STATE(VARBIND);
                }
            }
            break;

            case DONE:
                return true;
        }
    }
    return SNMP_ERROR_OK;
}

SNMP_PACKET_PARSE_ERROR SNMPPacket::parseFrom(unsigned char* buf, size_t max_len){
    SNMP_LOGD("Parsing %ld bytes\n", max_len);
    if(buf[0] != 0x30) {
        SNMP_LOGD("First byte error\n");
        return SNMP_PARSE_ERROR_MAGIC_BYTE;
    }

    packet = asn_new<ComplexType>(STRUCTURE);
    if(!packet){
        SNMP_LOGE("SNMPPacket::parseFrom: pool exhausted (root ComplexType). Raise SNMP_POOL_ASN_OBJECTS.\n");
        return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;
    }

    SNMP_BUFFER_PARSE_ERROR decodePacket = packet->fromBuffer(buf, max_len);
    if(decodePacket <= 0){
        SNMP_LOGD("failed to fromBuffer\n");
        return decodePacket;
    }

    // we now have a full ASN.1 packet in SNMPPacket
    return parsePacket(packet, SNMPVERSION);
}

int SNMPPacket::serialiseInto(uint8_t* buf, size_t max_len){
    if(this->build()){
        return this->packet->serialise(buf, max_len);
    }
    return 0;
}

bool SNMPPacket::_build_pdu_envelope(BuildPDUHeaderFn fill_pdu, void* userdata){
    asn_delete(this->packet);

    ComplexType* root = asn_new<ComplexType>(STRUCTURE);
    if(!root){
        SNMP_LOGE("_build_pdu_envelope: pool exhausted (root). Raise SNMP_POOL_ASN_OBJECTS.\n");
        this->packet = nullptr;
        return false;
    }
    root->_ownsChildren = true;
    this->packet = root;

    if(this->snmpVersionPtr)
        root->addValueToListRaw(asn_new<IntegerType>(this->snmpVersionPtr->_value));
    else
        root->addValueToListRaw(asn_new<IntegerType>(this->snmpVersion));

    if(this->communityStringPtr)
        root->addValueToListRaw(asn_new<OctetType>(this->communityStringPtr->_value, this->communityStringPtr->_valueLen));
    else
        root->addValueToListRaw(asn_new<OctetType>(this->communityString));

    ComplexType* snmpPDU = asn_new<ComplexType>(this->packetPDUType);
    if(!snmpPDU){
        SNMP_LOGE("_build_pdu_envelope: pool exhausted (snmpPDU). Raise SNMP_POOL_ASN_OBJECTS.\n");
        return false;
    }
    snmpPDU->_ownsChildren = true;

    if(!fill_pdu(snmpPDU, userdata)) return false;

    ComplexType* varBindList = this->generateVarBindListRaw();
    if(!varBindList) return false;

    snmpPDU->addValueToListRaw(varBindList);
    root->addValueToListRaw(snmpPDU);

    return true;
}

static bool _packet_build_fill_pdu(ComplexType* snmpPDU, void* userdata){
    SNMPPacket* self = static_cast<SNMPPacket*>(userdata);
    if(self->requestIDPtr)
        snmpPDU->addValueToListRaw(asn_new<IntegerType>(self->requestIDPtr->_value));
    else
        snmpPDU->addValueToListRaw(asn_new<IntegerType>(self->requestID));

    snmpPDU->addValueToListRaw(asn_new<IntegerType>(self->errorStatus.errorStatus));
    snmpPDU->addValueToListRaw(asn_new<IntegerType>(self->errorIndex.errorIndex));
    return true;
}

bool SNMPPacket::build(){
    return _build_pdu_envelope(_packet_build_fill_pdu, this);
}

void SNMPPacket::setCommunityString(const char *CommunityString){
    this->communityStringPtr = nullptr;
    size_t len = strlen(CommunityString);
    if(len > SNMP_MAX_COMMUNITY_LEN) len = SNMP_MAX_COMMUNITY_LEN;
    memcpy(this->communityString, CommunityString, len);
    this->communityString[len] = 0;
}

void SNMPPacket::setRequestID(snmp_request_id_t RequestId){
    this->requestIDPtr = nullptr;
    this->requestID = RequestId;
}

bool SNMPPacket::setPDUType(ASN_TYPE responseType){
    if(responseType >= ASN_PDU_TYPE_MIN_VALUE && responseType <= ASN_PDU_TYPE_MAX_VALUE){
        //TODO: check that we're a valid response type
        this->packetPDUType = responseType;
        return true;
    }
    return false;
}

void SNMPPacket::setVersion(SNMP_VERSION SnmpVersion){
    this->snmpVersionPtr = nullptr;
    this->snmpVersion = SnmpVersion;
}

ComplexType* SNMPPacket::generateVarBindListRaw(){
    SNMP_LOGD("generateVarBindListRaw from SNMPPacket");
    ComplexType* list = asn_new<ComplexType>(STRUCTURE);
    if(!list){
        SNMP_LOGE("SNMPPacket::generateVarBindListRaw: pool exhausted (list). Raise SNMP_POOL_ASN_OBJECTS.\n");
        return nullptr;
    }
    list->_ownsChildren = true;

    for(int vbIdx = 0; vbIdx < this->varbindCount; vbIdx++){
        const VarBind& varBindItem = this->varbindList[vbIdx];
        ComplexType* varBind = asn_new<ComplexType>(STRUCTURE);
        if(!varBind){
            SNMP_LOGE("SNMPPacket::generateVarBindListRaw: pool exhausted (vb %d/%d).\n", vbIdx, this->varbindCount);
            asn_delete(list);
            return nullptr;
        }
        varBind->_ownsChildren = false;

        if(varBindItem.oid){
            varBind->addValueToListRaw(varBindItem.oid);
        } else {
            varBind->addValueToListRaw(asn_new<NullType>());
        }

        if(varBindItem.value){
            varBind->addValueToListRaw(varBindItem.value);
        } else {
            varBind->addValueToListRaw(asn_new<NullType>());
        }

        list->addValueToListRaw(varBind);
    }

    return list;
}

snmp_request_id_t SNMPPacket::generate_request_id(){
    //NOTE: do not generate 0
    snmp_request_id_t request_id = 0;
    while(request_id == 0){
        request_id |= rand();
        request_id <<= 8;
        request_id |= rand();
    }
    return request_id;
}
