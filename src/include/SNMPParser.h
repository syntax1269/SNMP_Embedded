#ifndef SNMP_PARSER_h
#define SNMP_PARSER_h

#include "include/defs.h"

#include "include/SNMPPacket.h"
#include "include/SNMPResponse.h"
#include "include/ValueCallbacks.h"

typedef void (*informCB)(void* ctx, snmp_request_id_t, bool);

bool handleGetRequestPDU(ValueCallback* const *callbacks, int callbacksCount, const VarBind* varbindList, int varbindCount, VarBind outResponseList[], int &outResponseCount, SNMP_VERSION version, bool isGetNextRequest);
bool handleSetRequestPDU(ValueCallback* const *callbacks, int callbacksCount, const VarBind* varbindList, int varbindCount, VarBind outResponseList[], int &outResponseCount, SNMP_VERSION version);
bool handleGetBulkRequestPDU(ValueCallback* const *callbacks, int callbacksCount, const VarBind* varbindList, int varbindCount, VarBind outResponseList[], int &outResponseCount, unsigned int nonRepeaters, unsigned int maxRepititions, bool *outOverflow);

SNMP_ERROR_RESPONSE handlePacket(uint8_t* buffer, int packetLength, int* responseLength, int max_packet_size, ValueCallback* const *callbacks, int callbacksCount, const char *_community, const char *_readOnlyCommunity, informCB = nullptr, void* ctx = nullptr);

#endif