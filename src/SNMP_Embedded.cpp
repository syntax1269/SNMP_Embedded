#include "SNMP_Embedded.h"

const char* SNMP_TAG = "SNMP";
SNMPAgent* SNMPAgent::agents[SNMP_MAX_AGENTS] = {nullptr};
int SNMPAgent::agentsCount = 0;

void SNMPAgent::setUDP(UDP* udp){
    if(this->udpCount >= SNMP_MAX_UDP_PER_AGENT){
        SNMP_LOGE("setUDP: _udp[] full (%d slots). Raise SNMP_MAX_UDP_PER_AGENT.\n", SNMP_MAX_UDP_PER_AGENT);
        this->begin();
        return;
    }
    this->_udp[this->udpCount++] = udp;
    this->begin();
}

void SNMPAgent::begin(){
    this->restartUDP();
}

void SNMPAgent::begin(const char* prefix){
    size_t len = strlen(prefix);
    if(len > SNMP_MAX_OID_STR_LEN) len = SNMP_MAX_OID_STR_LEN;
    memcpy(oidPrefix, prefix, len);
    oidPrefix[len] = 0;
    this->begin();
}

void SNMPAgent::stop(){
    for(int i = 0; i < udpCount; i++){
        _udp[i]->stop();
    }
}

SNMP_ERROR_RESPONSE SNMPAgent::loop(){
    /* The startup-baseline guarantee lives inside ASNPool::resetAll()
     * (the single choke point) — see BER.h. loop()'s own resetAll() therefore
     * needs no separate call here, and a trap sent before the first loop()
     * tick is covered the same way. Explicit freezePermCount() in setup()
     * remains supported and takes precedence. */
    ASNPool::resetAll();

    for(int i = 0; i < udpCount; i++){
        UDP* udp = _udp[i];
        int packetLength = udp->parsePacket();
        if(packetLength > 0){
            SNMP_LOGI("loop: UDP[%d] parsePacket=%d bytes remote=%s:%d\n",
                      i, packetLength, udp->remoteIP().toString().c_str(), udp->remotePort());

            if(packetLength < 0 || packetLength > MAX_SNMP_PACKET_LENGTH){
                SNMP_LOGW("Incoming packet too large: %d\n", packetLength);
                return SNMP_REQUEST_TOO_LARGE;
            }

            memset(_packetBuffer, 0, MAX_SNMP_PACKET_LENGTH);

            int readBytes = udp->read(_packetBuffer, packetLength);
            if(readBytes != packetLength){
                SNMP_LOGW("Packet length mismatch: expected: %d, actual: %d\n", packetLength, readBytes);
                return SNMP_REQUEST_INVALID;
            }
            SNMP_LOGI("loop: UDP[%d] read OK. Calling handlePacket(len=%d)...\n", i, packetLength);

            int responseLength = 0;
            SNMP_ERROR_RESPONSE response = handlePacket(_packetBuffer, packetLength, &responseLength, MAX_SNMP_PACKET_LENGTH, callbacks, callbacksCount, _community, _readOnlyCommunity, informCallback, (void*)this);
            SNMP_LOGI("loop: handlePacket -> ret=%d, responseLength=%d\n", (int)response, responseLength);
            if(response > 0 && response != SNMP_INFORM_RESPONSE_OCCURRED){
                SNMP_LOGI("loop: UDP TX beginPacket(remote=%s:%d) write=%d B ...",
                          udp->remoteIP().toString().c_str(), udp->remotePort(), responseLength);
                udp->beginPacket(udp->remoteIP(), udp->remotePort());
                udp->write(_packetBuffer, responseLength);
                bool ep = udp->endPacket();
                SNMP_LOGI(" done. endPacket=%d\n", (int)ep);

                if(!ep){
                    SNMP_LOGW("Failed to send response packet\n");
                }
            }

            if(response == SNMP_SET_OCCURRED){
                setOccurred = true;
            }

            this->handleInformQueue();
            return response;
        }
    }

    this->handleInformQueue();
    return SNMP_NO_PACKET;
}

SortableOIDType* SNMPAgent::buildOIDWithPrefix(const char *oid, bool overwritePrefix){
    SortableOIDType* newOid;
    if(oidPrefix[0] != 0 && !overwritePrefix){
        char temp[SNMP_MAX_OID_STR_LEN + 1];
        size_t prefixLen = strlen(oidPrefix);
        size_t oidLen = strlen(oid);
        if(prefixLen + oidLen > SNMP_MAX_OID_STR_LEN){
            oidLen = SNMP_MAX_OID_STR_LEN - prefixLen;
        }
        memcpy(temp, oidPrefix, prefixLen);
        memcpy(temp + prefixLen, oid, oidLen);
        temp[prefixLen + oidLen] = 0;
        newOid = asn_new<SortableOIDType>(temp);
    } else {
        newOid = asn_new<SortableOIDType>(oid);
    }
    if(newOid->valid){
        return newOid;
    }
    asn_delete(newOid);
    return nullptr;
}

ValueCallback* SNMPAgent::addReadWriteStringHandler(const char *oid, char** value, size_t max_len, bool isSettable, bool overwritePrefix){
    if(!value || !*value) return nullptr;

    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new StringCallback(oidType, value, max_len), isSettable);
}

ValueCallback *SNMPAgent::addReadOnlyStaticStringHandler(const char *oid, const char* value, bool overwritePrefix) {
    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new ReadOnlyStringCallback(oidType, value), false);
}


ValueCallback* SNMPAgent::addOpaqueHandler(const char *oid, uint8_t* value, size_t data_len, bool isSettable, bool overwritePrefix){
    if(!value) return nullptr;

    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new OpaqueCallback(oidType, value, data_len), isSettable);
}

ValueCallback* SNMPAgent::addIntegerHandler(const char *oid, int* value, bool isSettable, bool overwritePrefix){
    if(!value) return nullptr;

    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new IntegerCallback(oidType, value), isSettable);
}

ValueCallback* SNMPAgent::addReadOnlyIntegerHandler(const char *oid, int value, bool overwritePrefix){
    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) {
        return nullptr;
    }
    return addHandler(new StaticIntegerCallback(oidType, value), false);
}

ValueCallback* SNMPAgent::addDynamicIntegerHandler(const char *oid, GETINT_FUNC callback_func, bool overwritePrefix){
    if(!callback_func) {
        return nullptr;
    }

    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) {
        return nullptr;
    }

    return addHandler(new DynamicIntegerCallback(oidType, callback_func), false);
}

ValueCallback* SNMPAgent::addTimestampHandler(const char *oid, uint32_t* value, bool isSettable, bool overwritePrefix){
    if(!value) return nullptr;

    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new TimestampCallback(oidType, value), isSettable);
}

ValueCallback* SNMPAgent::addDynamicReadOnlyTimestampHandler(const char *oid, GETUINT_FUNC callback_func, bool overwritePrefix){
    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) {
        return nullptr;
    }
    return addHandler(new DynamicTimestampCallback(oidType, callback_func), false);
}

ValueCallback* SNMPAgent::addDynamicReadOnlyStringHandler(const char *oid, GETSTRING_FUNC callback_func, bool overwritePrefix){
    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) {
        return nullptr;
    }
    return addHandler(new DynamicStringCallback(oidType, callback_func), false);
}

ValueCallback* SNMPAgent::addOIDHandler(const char *oid, const char* value, bool overwritePrefix){
    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new OIDCallback(oidType, value), false);
}

ValueCallback* SNMPAgent::addCounter64Handler(const char *oid, uint64_t* value, bool overwritePrefix){
    if(!value) return nullptr;

    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new Counter64Callback(oidType, value), false);
}

ValueCallback* SNMPAgent::addCounter32Handler(const char *oid, uint32_t* value, bool overwritePrefix){
    if(!value) return nullptr;

    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new Counter32Callback(oidType, value), false);
}

ValueCallback* SNMPAgent::addGaugeHandler(const char *oid, uint32_t* value, bool overwritePrefix){
    if(!value) return nullptr;

    SortableOIDType* oidType = buildOIDWithPrefix(oid, overwritePrefix);
    if(!oidType) return nullptr;
    return addHandler(new Gauge32Callback(oidType, value), false);
}

ValueCallback * SNMPAgent::addHandler(ValueCallback *callback, bool isSettable) {
    if(!callback) return nullptr;
    callback->isSettable = isSettable;
    if(this->callbacksCount >= SNMP_MAX_CALLBACKS_PER_AGENT){
        SNMP_LOGE("addHandler: callbacks[] full (%d slots), OID %s NOT registered. Raise SNMP_MAX_CALLBACKS_PER_AGENT.\n",
                  SNMP_MAX_CALLBACKS_PER_AGENT, callback->OID ? callback->OID->string() : "(null)");
        delete callback;
        return nullptr;
    }
    this->callbacks[this->callbacksCount++] = callback;
    return callback;
}

bool SNMPAgent::removeHandler(ValueCallback* callback){
    return remove_handler(this->callbacks, this->callbacksCount, callback);
}

bool SNMPAgent::sortHandlers(){
    sort_handlers(this->callbacks, this->callbacksCount);
    return true;
}

void SNMPAgent::printAllOIDsTo(Print& out) const {
    char line[SNMP_MAX_OID_STR_LEN + 32];
    for(int i = 0; i < this->callbacksCount; i++){
        const ValueCallback* cb = this->callbacks[i];
        if(!cb || !cb->OID) continue;
        const char* oidStr = cb->OID->string();
        const char* typeStr = ValueCallback::getTypeName(cb->type);
        const char* tagStr = cb->getAccessTag();
        snprintf(line, sizeof(line), "[%2d] %s  %-10s %s\r\n",
                 i, oidStr, typeStr, tagStr);
        out.print(line);
    }
}

snmp_request_id_t SNMPAgent::sendTrapTo(SNMPTrap* trap, const IPAddress& ip, bool replaceQueuedRequests, int retries, int delay_ms){
    return queue_and_send_trap(this->informList, this->informCount, trap, ip, replaceQueuedRequests, retries, delay_ms);
}

void SNMPAgent::informCallback(void* ctx, snmp_request_id_t requestID, bool responseReceiveSuccess){
    if(!ctx) return;
    SNMPAgent* agent = static_cast<SNMPAgent*>(ctx);

    return inform_callback(agent->informList, agent->informCount, requestID, responseReceiveSuccess);
}

void SNMPAgent::handleInformQueue(){
    handle_inform_queue(this->informList, this->informCount);
}

void SNMPAgent::markTrapDeleted(SNMPTrap* trap){
    for(int i = 0; i < agentsCount; i++){
        SNMPAgent* agent = agents[i];
        if(!agent) continue;
        mark_trap_deleted(agent->informList, agent->informCount, trap);
    }
}

bool SNMPAgent::restartUDP() {
    bool all_ok = true;
    for(int i = 0; i < udpCount; i++){
        _udp[i]->stop();
        uint8_t ok = _udp[i]->begin(AgentUDPport);
        if(!ok){
            SNMP_LOGE("restartUDP: UDP[%d]->begin(port=%d) FAILED (returned 0). WiFi down? port already bound? check port permissions.\n",
                      i, (int)AgentUDPport);
            all_ok = false;
        }
    }
    return all_ok;
}
