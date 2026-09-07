#include "include/BERView.h"

#if SNMP_ZERO_COPY

#include "include/SNMPParser.h"
#include "include/BER.h"
#include "include/ValueCallbacks.h"

namespace {

/* OIDType stores at most SNMP_MAX_OID_SUBIDENTIFIERS + 1 encoded bytes,
 * including the 0x2b first arc byte.  Keep the complete response TLV in the
 * plan so Phase B never reads from the request buffer. */
struct OidWire {
    uint8_t bytes[SNMP_MAX_OID_SUBIDENTIFIERS + 3];
    uint16_t len;

    OidWire(): bytes(), len(0) {}
};

static bool makeOidWire(const uint8_t* content, size_t contentLen, OidWire* out){
    if(!content || !out || contentLen > SNMP_MAX_OID_SUBIDENTIFIERS + 1 || contentLen >= 0x80){
        return false;
    }
    out->bytes[0] = 0x06;
    out->bytes[1] = (uint8_t)contentLen;
    memcpy(out->bytes + 2, content, contentLen);
    out->len = (uint16_t)(contentLen + 2);
    return true;
}

static bool makeCallbackOidWire(ValueCallback* callback, OidWire* out){
    if(!callback || !callback->OID || !callback->OID->valid){
        return false;
    }
    return makeOidWire(callback->OID->encodedData(),
                       (size_t)callback->OID->encodedLen(), out);
}

static bool putOidWire(BerWriter& writer, const OidWire& oid){
    return writer.putBytes(oid.bytes, oid.len);
}

/* ValueCallback::getValueForCallback() already returns a pool-aware
 * shared_ptr.  Values decoded from the request need the same pool deleter. */
struct PoolDeleter {
    void operator()(BER_CONTAINER* value) const noexcept {
        asn_delete(value);
    }
};

static std::shared_ptr<BER_CONTAINER> poolShared(BER_CONTAINER* value){
    if(!value){
        return nullptr;
    }
    return std::shared_ptr<BER_CONTAINER>(value, PoolDeleter());
}

/* This is the same factory used by ComplexType::fromBuffer().  Keeping the
 * decode pass canonical is important: malformed values must be rejected
 * before any SET side effect, just as in the owning parser. */
static BER_CONTAINER* makeValueForTag(ASN_TYPE type){
    switch(type){
        case INTEGER:          return asn_new<IntegerType>();
        case STRING:           return asn_new<OctetType>();
        case OID:              return asn_new<OIDType>();
        case NULLTYPE:         return asn_new<NullType>();
        case NOSUCHOBJECT:     return asn_new<ImplicitNullType>(NOSUCHOBJECT);
        case NOSUCHINSTANCE:   return asn_new<ImplicitNullType>(NOSUCHINSTANCE);
        case ENDOFMIBVIEW:     return asn_new<ImplicitNullType>(ENDOFMIBVIEW);
        case NETWORK_ADDRESS:  return asn_new<NetworkAddress>();
        case TIMESTAMP:        return asn_new<TimestampType>();
        case COUNTER32:        return asn_new<Counter32>();
        case GAUGE32:          return asn_new<Gauge>();
        case COUNTER64:        return asn_new<Counter64>();
        case OPAQUE:           return asn_new<OpaqueType>();
        case STRUCTURE:
        case GetRequestPDU:
        case GetNextRequestPDU:
        case GetResponsePDU:
        case SetRequestPDU:
        case TrapPDU:
        case GetBulkRequestPDU:
        case InformRequestPDU:
        case Trapv2PDU:        return asn_new<ComplexType>(type);
        default:               return nullptr;
    }
}

/* Parse every request value before dispatch.  The owning parser does this
 * while constructing its ASN tree, so this pass preserves the same rejection
 * behavior and prevents SET side effects before a later malformed value is
 * discovered. */
static bool decodeRequestValues(const SnmpHeaderView& request,
                                std::shared_ptr<BER_CONTAINER>* decoded,
                                const uint8_t* packet,
                                size_t packetLength){
    const uint8_t* packetEnd = packet + packetLength;
    for(int i = 0; i < request.varbindCount; i++){
        const VarBindView& vb = request.vbs[i];
        if(vb.oidLen > SNMP_MAX_OID_SUBIDENTIFIERS + 1 ||
           !vb.oid || vb.oid[0] != 0x2b ||
           !vb.valueTlv || vb.valueTlvLen == 0 ||
           vb.valueTlv < packet ||
           vb.valueTlv + vb.valueTlvLen > packetEnd){
            return false;
        }

        BER_CONTAINER* raw = makeValueForTag((ASN_TYPE)vb.valueType);
        if(!raw){
            return false;
        }

        std::shared_ptr<BER_CONTAINER> value = poolShared(raw);
        int used = value->fromBuffer(vb.valueTlv, vb.valueTlvLen);
        if(used <= 0 || used != (int)vb.valueTlvLen){
            return false;
        }
        decoded[i] = value;
    }
    return true;
}

/* A response plan owns all data needed after Phase A.  In particular, OIDs
 * are copied out of the UDP buffer before Phase B starts. */
struct PlannedVarBind {
    OidWire oid;
    std::shared_ptr<BER_CONTAINER> value;
    uint8_t nullTag;
    SNMP_ERROR_STATUS error;
    int responseIndex;

    PlannedVarBind(): oid(), value(), nullTag(0), error(NO_ERROR), responseIndex(0) {}
};

struct ResponsePlan {
    PlannedVarBind varbinds[SNMP_MAX_VARBINDS];
    int count;
    SNMP_ERROR_STATUS lastError;
    int lastErrorIndex;

    ResponsePlan(): varbinds(), count(0), lastError(NO_ERROR), lastErrorIndex(0) {}

    bool add(const OidWire& oid, const std::shared_ptr<BER_CONTAINER>& value,
             uint8_t nullTag, SNMP_ERROR_STATUS error){
        if(count >= SNMP_MAX_VARBINDS){
            return false;
        }
        PlannedVarBind& item = varbinds[count];
        item.oid = oid;
        item.value = value;
        item.nullTag = nullTag;
        item.error = error;
        item.responseIndex = ++count;
        if(error != NO_ERROR){
            lastError = error;
            lastErrorIndex = item.responseIndex;
        }
        return true;
    }
};

static bool addRequestOidPlan(ResponsePlan& plan, const VarBindView& vb,
                              const std::shared_ptr<BER_CONTAINER>& value,
                              uint8_t nullTag, SNMP_ERROR_STATUS error){
    OidWire oid;
    if(!makeOidWire(vb.oid, vb.oidLen, &oid)){
        return false;
    }
    return plan.add(oid, value, nullTag, error);
}

static bool addCallbackOidPlan(ResponsePlan& plan, ValueCallback* callback,
                               const std::shared_ptr<BER_CONTAINER>& value,
                               uint8_t nullTag, SNMP_ERROR_STATUS error){
    OidWire oid;
    if(!makeCallbackOidWire(callback, &oid)){
        return false;
    }
    return plan.add(oid, value, nullTag, error);
}

static bool stageGet(ResponsePlan& plan,
                     ValueCallback* const* callbacks, int callbacksCount,
                     const SnmpHeaderView& request, bool getNext){
    for(int i = 0; i < request.varbindCount; i++){
        const VarBindView& vb = request.vbs[i];
        ValueCallback* callback = ValueCallback::findCallbackForSlice(
            callbacks, callbacksCount, vb.oid, (int)vb.oidLen, getNext, 0, nullptr);

        if(!callback){
            if(!addRequestOidPlan(plan, vb, nullptr,
                                  getNext ? ENDOFMIBVIEW : NOSUCHOBJECT, NO_ERROR)){
                return false;
            }
            continue;
        }

        std::shared_ptr<BER_CONTAINER> value =
            ValueCallback::getValueForCallback(callback);
        if(!value){
            SNMP_ERROR_STATUS error =
                SNMP_ERROR_VERSION_CTRL(GEN_ERR, (SNMP_VERSION)request.version);
            if(!addCallbackOidPlan(plan, callback, nullptr, NULLTYPE, error)){
                return false;
            }
            continue;
        }

        if(!addCallbackOidPlan(plan, callback, value, 0, NO_ERROR)){
            return false;
        }
    }
    return true;
}

static bool stageGetBulk(ResponsePlan& plan,
                         ValueCallback* const* callbacks, int callbacksCount,
                         const SnmpHeaderView& request){
    const unsigned int nonRepeaters =
        (unsigned int)(uint32_t)request.errorStatus;
    const unsigned int maxRepetitions =
        (unsigned int)(uint32_t)request.errorIndex;
    const unsigned int nonRepeaterCount =
        nonRepeaters < (unsigned int)request.varbindCount
            ? nonRepeaters : (unsigned int)request.varbindCount;

    /* RFC 3416 non-repeaters in this implementation use walk semantics and
     * return endOfMibView on a miss.  Successful rows echo the request OID. */
    for(unsigned int i = 0; i < nonRepeaterCount; i++){
        const VarBindView& vb = request.vbs[i];
        ValueCallback* callback = ValueCallback::findCallbackForSlice(
            callbacks, callbacksCount, vb.oid, (int)vb.oidLen, true, 0, nullptr);

        if(!callback){
            if(!addRequestOidPlan(plan, vb, nullptr, ENDOFMIBVIEW, NO_ERROR)){
                return false;
            }
            continue;
        }

        std::shared_ptr<BER_CONTAINER> value =
            ValueCallback::getValueForCallback(callback);
        if(!value){
            if(!addCallbackOidPlan(plan, callback, nullptr, NULLTYPE, GEN_ERR)){
                return false;
            }
            continue;
        }

        if(!addRequestOidPlan(plan, vb, value, 0, NO_ERROR)){
            return false;
        }
    }

    /* Repeaters walk from the request OID, then from each selected handler
     * OID.  The cursor is always staged data, never a request-buffer slice. */
    for(unsigned int i = nonRepeaterCount;
        i < (unsigned int)request.varbindCount; i++){
        OidWire cursor;
        if(!makeOidWire(request.vbs[i].oid, request.vbs[i].oidLen, &cursor)){
            return false;
        }
        int foundAt = 0;

        for(unsigned int repetition = 0; repetition < maxRepetitions; repetition++){
            ValueCallback* callback = ValueCallback::findCallbackForSlice(
                callbacks, callbacksCount, cursor.bytes + 2, (int)cursor.len - 2,
                true, foundAt, &foundAt);

            if(!callback){
                if(!plan.add(cursor, nullptr, ENDOFMIBVIEW, NO_ERROR)){
                    return false;
                }
                break;
            }

            OidWire callbackOid;
            if(!makeCallbackOidWire(callback, &callbackOid)){
                return false;
            }
            std::shared_ptr<BER_CONTAINER> value =
                ValueCallback::getValueForCallback(callback);
            if(!value){
                if(!plan.add(callbackOid, nullptr, NULLTYPE, GEN_ERR)){
                    return false;
                }
                break;
            }

            if(!plan.add(callbackOid, value, 0, NO_ERROR)){
                return false;
            }
            cursor = callbackOid;
        }
    }
    return true;
}

static bool stageSet(ResponsePlan& plan,
                     ValueCallback* const* callbacks, int callbacksCount,
                     const SnmpHeaderView& request,
                     const std::shared_ptr<BER_CONTAINER>* decoded){
    for(int i = 0; i < request.varbindCount; i++){
        const VarBindView& vb = request.vbs[i];
        ValueCallback* callback = ValueCallback::findCallbackForSlice(
            callbacks, callbacksCount, vb.oid, (int)vb.oidLen, false, 0, nullptr);

        if(!callback){
            SNMP_ERROR_STATUS error = SNMP_ERROR_VERSION_CTRL_DEF(
                NOT_WRITABLE, (SNMP_VERSION)request.version, NO_SUCH_NAME);
            if(!addRequestOidPlan(plan, vb, nullptr, NULLTYPE, error)){
                return false;
            }
            continue;
        }

        if(callback->type != (ASN_TYPE)vb.valueType){
            SNMP_ERROR_STATUS error = SNMP_ERROR_VERSION_CTRL_DEF(
                WRONG_TYPE, (SNMP_VERSION)request.version, BAD_VALUE);
            if(!addRequestOidPlan(plan, vb, nullptr, NULLTYPE, error)){
                return false;
            }
            continue;
        }

        if(!callback->isSettable){
            SNMP_ERROR_STATUS error = SNMP_ERROR_VERSION_CTRL(
                READ_ONLY, (SNMP_VERSION)request.version);
            if(!addRequestOidPlan(plan, vb, nullptr, NULLTYPE, error)){
                return false;
            }
            continue;
        }

        if(!decoded[i]){
            return false;
        }
        SNMP_ERROR_STATUS setError =
            ValueCallback::setValueForCallback(callback, decoded[i]);
        if(setError != NO_ERROR){
            SNMP_ERROR_STATUS error = SNMP_ERROR_VERSION_CTRL(
                setError, (SNMP_VERSION)request.version);
            if(!addCallbackOidPlan(plan, callback, nullptr, NULLTYPE, error)){
                return false;
            }
            continue;
        }

        std::shared_ptr<BER_CONTAINER> fresh =
            ValueCallback::getValueForCallback(callback);
        if(!fresh){
            SNMP_ERROR_STATUS error = SNMP_ERROR_VERSION_CTRL(
                GEN_ERR, (SNMP_VERSION)request.version);
            if(!addCallbackOidPlan(plan, callback, nullptr, NULLTYPE, error)){
                return false;
            }
            continue;
        }

        if(!addCallbackOidPlan(plan, callback, fresh, 0, NO_ERROR)){
            return false;
        }
    }
    return true;
}

static bool writeValue(BerWriter& writer, const std::shared_ptr<BER_CONTAINER>& value){
    if(!value){
        return false;
    }
    uint8_t scratch[SNMP_POOL_SLOT_SIZE];
    int used = value->wireSerialise(scratch, sizeof(scratch));
    if(used <= 0 || (size_t)used > sizeof(scratch)){
        return false;
    }
    return writer.putBytes(scratch, (size_t)used);
}

static bool writeEnvelopeHeader(BerWriter& writer,
                                const SnmpHeaderView& request,
                                const uint8_t* community, size_t communityLen,
                                SNMP_ERROR_STATUS errorStatus,
                                int errorIndex,
                                BerWriter::Marker* root,
                                BerWriter::Marker* pdu,
                                BerWriter::Marker* varbindList){
    if(!writer.beginScope(STRUCTURE, root) ||
       !writer.putInteger((long)request.version) ||
       !writer.putOctets(STRING, community, communityLen) ||
       !writer.beginScope(GetResponsePDU, pdu) ||
       !writer.putInteger((long)(uint32_t)request.requestID) ||
       !writer.putInteger((long)errorStatus) ||
       !writer.putInteger((long)errorIndex) ||
       !writer.beginScope(STRUCTURE, varbindList)){
        return false;
    }
    return true;
}

static bool writeErrorResponse(uint8_t* buffer, size_t maxPacketSize,
                               const SnmpHeaderView& request,
                               const uint8_t* community, size_t communityLen,
                               SNMP_ERROR_STATUS errorStatus,
                               int* responseLength){
    BerWriter writer(buffer, maxPacketSize);
    BerWriter::Marker root, pdu, varbindList;
    if(!writeEnvelopeHeader(writer, request, community, communityLen,
                            errorStatus, 0, &root, &pdu, &varbindList) ||
       !writer.endScope(&varbindList) ||
       !writer.endScope(&pdu) ||
       !writer.endScope(&root)){
        return false;
    }
    *responseLength = (int)writer.length();
    return true;
}

static bool writeNormalResponse(uint8_t* buffer, size_t maxPacketSize,
                                const SnmpHeaderView& request,
                                const uint8_t* community, size_t communityLen,
                                const ResponsePlan& plan,
                                int* responseLength){
    BerWriter writer(buffer, maxPacketSize);
    BerWriter::Marker root, pdu, varbindList;
    if(!writeEnvelopeHeader(writer, request, community, communityLen,
                            plan.lastError,
                            plan.lastError == NO_ERROR ? 0 : plan.lastErrorIndex,
                            &root, &pdu, &varbindList)){
        return false;
    }

    for(int i = 0; i < plan.count; i++){
        const PlannedVarBind& item = plan.varbinds[i];
        BerWriter::Marker varbind;
        if(!writer.beginScope(STRUCTURE, &varbind) ||
           !putOidWire(writer, item.oid)){
            return false;
        }
        if(item.value){
            if(!writeValue(writer, item.value)){
                return false;
            }
        } else if(!writer.putNull(item.nullTag)){
            return false;
        }
        if(!writer.endScope(&varbind)){
            return false;
        }
    }

    if(!writer.endScope(&varbindList) ||
       !writer.endScope(&pdu) ||
       !writer.endScope(&root)){
        return false;
    }
    *responseLength = (int)writer.length();
    return true;
}

} /* namespace */

SNMP_ERROR_RESPONSE handlePacketInPlace(uint8_t* buffer, int packetLength,
                                        int* responseLength, int max_packet_size,
                                        ValueCallback* const* callbacks,
                                        int callbacksCount,
                                        const char* community,
                                        const char* readOnlyCommunity,
                                        informCB informCallback, void* ctx){
    if(responseLength){
        *responseLength = 0;
    }
    if(!buffer || packetLength <= 0 || !responseLength || max_packet_size <= 0){
        return SNMP_REQUEST_INVALID;
    }

    SnmpHeaderView request;
    if(!snmp_ber_peek_packet(buffer, (size_t)packetLength, &request)){
        return SNMP_REQUEST_INVALID;
    }
    if(request.varbindsTruncated || request.varbindCount > SNMP_MAX_VARBINDS){
        return SNMP_REQUEST_INVALID;
    }

    /* Decode all request values before any callback or response write. */
    std::shared_ptr<BER_CONTAINER> decoded[SNMP_MAX_VARBINDS];
    if(!decodeRequestValues(request, decoded, buffer, (size_t)packetLength)){
        return SNMP_REQUEST_INVALID;
    }

    if(request.pduType == GetResponsePDU){
        if(informCallback){
            informCallback(ctx, request.requestID, request.errorStatus == 0);
        } else {
            SNMP_LOGW("Not sure what to do with Inform\n");
        }
        return SNMP_INFORM_RESPONSE_OCCURRED;
    }

    /* Match the owning parser's C-string community semantics, including its
     * explicit empty-string result when the wire community exceeds the cap.
     * Keep a separate raw copy because the response echoes the wire octets. */
    uint8_t communityWire[SNMP_MAX_STRING_LEN];
    size_t communityWireLen = request.communityLen;
    if(communityWireLen > sizeof(communityWire)){
        communityWireLen = sizeof(communityWire);
    }
    if(communityWireLen > 0){
        memcpy(communityWire, request.community, communityWireLen);
    }

    char communityText[SNMP_MAX_COMMUNITY_LEN + 1];
    if(request.communityLen > SNMP_MAX_COMMUNITY_LEN){
        communityText[0] = 0;
    } else {
        if(request.communityLen > 0){
            memcpy(communityText, request.community, request.communityLen);
        }
        communityText[request.communityLen] = 0;
    }

    SNMP_PERMISSION permission = SNMP_PERM_NONE;
    if(readOnlyCommunity && readOnlyCommunity[0] != 0 &&
       strcmp(readOnlyCommunity, communityText) == 0){
        permission = SNMP_PERM_READ_ONLY;
    }
    if(community && strcmp(community, communityText) == 0){
        permission = SNMP_PERM_READ_WRITE;
    }
    if(permission == SNMP_PERM_NONE){
        return SNMP_REQUEST_INVALID_COMMUNITY;
    }

    ResponsePlan plan;
    bool globalError = false;
    SNMP_ERROR_STATUS globalErrorStatus = GEN_ERR;
    SNMP_ERROR_RESPONSE successResponse = SNMP_NO_ERROR;

    switch(request.pduType){
        case GetRequestPDU:
            if(!stageGet(plan, callbacks, callbacksCount, request, false)){
                globalError = true;
                globalErrorStatus = TOO_BIG;
            }
            successResponse = SNMP_GET_OCCURRED;
            break;

        case GetNextRequestPDU:
            if(!stageGet(plan, callbacks, callbacksCount, request, true)){
                globalError = true;
                globalErrorStatus = TOO_BIG;
            }
            successResponse = SNMP_GETNEXT_OCCURRED;
            break;

        case GetBulkRequestPDU:
            if(request.version != SNMP_VERSION_2C){
                globalError = true;
                globalErrorStatus = GEN_ERR;
            } else if(!stageGetBulk(plan, callbacks, callbacksCount, request)){
                globalError = true;
                globalErrorStatus = TOO_BIG;
            }
            successResponse = SNMP_GETBULK_OCCURRED;
            break;

        case SetRequestPDU:
            if(permission != SNMP_PERM_READ_WRITE){
                globalError = true;
                globalErrorStatus = NO_ACCESS;
            } else if(!stageSet(plan, callbacks, callbacksCount, request, decoded)){
                globalError = true;
                globalErrorStatus = TOO_BIG;
            }
            successResponse = SNMP_SET_OCCURRED;
            break;

        default:
            globalError = true;
            globalErrorStatus = GEN_ERR;
            successResponse = SNMP_ERROR_PACKET_SENT;
            break;
    }

    /* The response community is copied out before Phase B because the writer
     * overwrites the original request envelope in place. */
    if(globalError){
        if(writeErrorResponse(buffer, (size_t)max_packet_size, request,
                              communityWire, communityWireLen,
                              globalErrorStatus, responseLength)){
            return SNMP_ERROR_PACKET_SENT;
        }
        if(writeErrorResponse(buffer, (size_t)max_packet_size, request,
                              communityWire, communityWireLen,
                              TOO_BIG, responseLength)){
            return SNMP_ERROR_PACKET_SENT;
        }
        return SNMP_FAILED_SERIALISATION;
    }

    if(writeNormalResponse(buffer, (size_t)max_packet_size, request,
                           communityWire, communityWireLen,
                           plan, responseLength)){
        return successResponse;
    }

    /* A normal response that does not fit is rebuilt as the small RFC 3416
     * tooBig response, just like the owning path.  SET side effects have
     * already occurred in Phase A, matching the owning path's ordering. */
    if(writeErrorResponse(buffer, (size_t)max_packet_size, request,
                          communityWire, communityWireLen,
                          TOO_BIG, responseLength)){
        return SNMP_ERROR_PACKET_SENT;
    }
    return SNMP_FAILED_SERIALISATION;
}

#endif /* SNMP_ZERO_COPY */
