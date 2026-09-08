#include "include/SNMPParser.h"

static SNMP_PERMISSION getPermissionOfRequest(const SNMPPacket& request, const char* _community, const char* _readOnlyCommunity){
    SNMP_PERMISSION requestPermission = SNMP_PERM_NONE;
    SNMP_LOGD("community string in packet: %s\n", request.communityString);

    if(_readOnlyCommunity[0] != 0 && strcmp(_readOnlyCommunity, request.communityString) == 0) {
        requestPermission = SNMP_PERM_READ_ONLY;
    }

    if(strcmp(_community, request.communityString) == 0) {
        requestPermission = SNMP_PERM_READ_WRITE;
    }
    return requestPermission;
}

SNMP_ERROR_RESPONSE handlePacket(uint8_t* buffer, int packetLength, int* responseLength, int max_packet_size, ValueCallback* const *callbacks, int callbacksCount, const char* _community, const char* _readOnlyCommunity, informCB informCallback, void* ctx){
    SNMPPacket request;

    SNMP_PACKET_PARSE_ERROR parseResult = request.parseFrom(buffer, packetLength);
    if(parseResult <= 0){
        SNMP_LOGW("Received Error code: %d when attempting to parse\n", parseResult);
        ASNPool::malformedPackets++;   /* v3.4.4 (P1) */
        return SNMP_REQUEST_INVALID;
    }

    SNMP_LOGD("Valid SNMP Packet!");

    if(request.packetPDUType == GetResponsePDU){
        SNMP_LOGD("Received GetResponse! probably as a result of a recent InformTrap: %lu", request.requestID);
        if(informCallback){
            informCallback(ctx, request.requestID, !request.errorStatus.errorStatus);
        } else {
            SNMP_LOGW("Not sure what to do with Inform\n");
        }
        return SNMP_INFORM_RESPONSE_OCCURRED;
    }

    SNMP_PERMISSION requestPermission = getPermissionOfRequest(request, _community, _readOnlyCommunity);
    if(requestPermission == SNMP_PERM_NONE){
        SNMP_LOGW("Invalid communitystring provided: %s, no response to give\n", request.communityString);
        ASNPool::packetsRejected++;   /* v3.4.4 (P1): valid parse, community denied */
        return SNMP_REQUEST_INVALID_COMMUNITY;
    }

    SNMPResponse response = SNMPResponse(request);

    VarBind outResponseList[SNMP_MAX_VARBINDS];
    int outResponseCount = 0;

    bool pass = false;
    SNMP_ERROR_RESPONSE handleStatus = SNMP_NO_ERROR;
    SNMP_ERROR_STATUS globalError = GEN_ERR;

    switch(request.packetPDUType){
        case GetRequestPDU:
        case GetNextRequestPDU:
            pass = handleGetRequestPDU(callbacks, callbacksCount, request.varbindList, request.varbindCount, outResponseList, outResponseCount, request.snmpVersion, request.packetPDUType == GetNextRequestPDU);
            handleStatus = request.packetPDUType == GetRequestPDU ? SNMP_GET_OCCURRED : SNMP_GETNEXT_OCCURRED;
        break;
        case GetBulkRequestPDU:
            if(request.snmpVersion != SNMP_VERSION_2C){
                SNMP_LOGD("Received GetBulkRequest in SNMP_VERSION_1");
                pass = false;
                globalError = GEN_ERR;
            } else {
                /* A GetBulk whose repeater expansion exceeds
                 * SNMP_MAX_VARBINDS now answers with an RFC 3416 tooBig
                 * error PDU instead of silently truncating the response
                 * varbind list. */
                bool bulkOverflow = false;
                pass = handleGetBulkRequestPDU(callbacks, callbacksCount, request.varbindList, request.varbindCount, outResponseList, outResponseCount, request.errorStatus.nonRepeaters, request.errorIndex.maxRepititions, &bulkOverflow);
                if(bulkOverflow){
                    SNMP_LOGW("GetBulk expansion exceeds SNMP_MAX_VARBINDS (%d): responding tooBig (was: silently truncated). Raise SNMP_MAX_VARBINDS via sketch #define before #include <SNMP_Embedded.h>.\n", SNMP_MAX_VARBINDS);
                    pass = false;
                    globalError = TOO_BIG;
                    ASNPool::tooBigResponses++;   /* v3.4.4 (P1) */
                }
                handleStatus = SNMP_GETBULK_OCCURRED;
            }
        break;
        case SetRequestPDU:
            if(requestPermission != SNMP_PERM_READ_WRITE){
                SNMP_LOGD("Attempting to perform a SET without required permissions");
                pass = false;
                globalError = NO_ACCESS;
            } else {
                pass = handleSetRequestPDU(callbacks, callbacksCount, request.varbindList, request.varbindCount, outResponseList, outResponseCount, request.snmpVersion);
                handleStatus = SNMP_SET_OCCURRED;
            }
        break;
        default:
            SNMP_LOGD("Not sure what to do with SNMP PDU of type: %d\n", request.packetPDUType);
            handleStatus = SNMP_UNKNOWN_PDU_OCCURRED;
            pass = false;
        break;
    }

    /* NOTE: no explicit request.~SNMPPacket() here. The automatic destructor at
     * scope exit destroys `request` exactly once, AFTER response.serialiseInto().
     * An earlier explicit call double-destroyed every pool-backed parse object
     * (refcount hit 0 twice) and ASNPool::release() decremented usedCount twice
     * per object — corrupting the pool counter until slots could be handed to
     * two live objects. Symptom on ESP8266: degraded/short GetBulk responses
     * under trap concurrency, with no exhaustion logs. */

    if(pass){
        for(int idx = 0; idx < outResponseCount; idx++){
            const VarBind& item = outResponseList[idx];
            if(item.errorStatus != NO_ERROR){
                response.addErrorResponse(item);
            } else {
                response.addResponse(item);
            }
        }
    } else {
        SNMP_LOGD("Handled error when building request, error: %d, sending error PDU", globalError);
        response.setGlobalError(globalError, 0, true);
        handleStatus = SNMP_ERROR_PACKET_SENT;
    }

    memset(buffer, 0, max_packet_size);

    *responseLength = response.serialiseInto(buffer, max_packet_size);
    if(*responseLength <= 0){
        /* v3.3.2: the response builder materializes before serializing, so a
         * response can be fully built yet exceed the packet buffer (long OIDs,
         * string values, big SET echoes).  Former behavior returned
         * SNMP_FAILED_SERIALISATION with NO response — the manager waits out
         * its full timeout on a request the agent actually processed.  RFC
         * 3416 §4.2.x requires the agent to answer tooBig instead whenever it
         * cannot return a well-formed response within its message-size limit.
         * A tooBig error PDU is tiny (request OID echo only) and cannot itself
         * overflow, so rebuilding into the same buffer is always safe. */
        SNMP_LOGW("Response of %d varbind(s) exceeds packet budget (%d B): rebuilding as tooBig (RFC 3416).\n",
                  response.size(), (int)max_packet_size);
        ASNPool::tooBigResponses++;   /* v3.4.4 (P1): response-fit tooBig */
        SNMPResponse tooBigResponse(request);
        tooBigResponse.setGlobalError(TOO_BIG, 0, true);
        memset(buffer, 0, max_packet_size);
        *responseLength = tooBigResponse.serialiseInto(buffer, max_packet_size);
        if(*responseLength <= 0){
            SNMP_LOGE("tooBig rebuild also failed to serialise");
            return SNMP_FAILED_SERIALISATION;
        }
        return SNMP_ERROR_PACKET_SENT;
    }

    return handleStatus;
}