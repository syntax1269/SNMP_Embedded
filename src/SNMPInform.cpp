#include "include/SNMPInform.h"
#include "SNMPTrap.h"

#ifdef COMPILING_TESTS
    #include <tests/required/millis.h>
#endif

inline void delete_inform(struct InformItem* inform){
    free(inform);
}

static int remove_informs_matching(struct InformItem** informList, int& informCount,
                                   bool (*predicate)(struct InformItem*, void*),
                                   void* ctx) {
    int removed = 0;
    int writeIdx = 0;
    for(int i = 0; i < informCount; i++){
        if(predicate(informList[i], ctx)){
            delete_inform(informList[i]);
            informList[i] = nullptr;
            removed++;
        } else {
            if(writeIdx != i){
                informList[writeIdx] = informList[i];
                informList[i] = nullptr;
            }
            writeIdx++;
        }
    }
    informCount = writeIdx;
    for(int i = informCount; i < SNMP_MAX_TRAPS_INFLIGHT; i++){
        informList[i] = nullptr;
    }
    return removed;
}

struct QSt_match_trap { SNMPTrap* trap; };
static bool pred_match_trap(struct InformItem* item, void* ctx){
    QSt_match_trap* c = (QSt_match_trap*)ctx;
    return item->trap == c->trap;
}

struct QSt_match_id { snmp_request_id_t id; };
static bool pred_match_request_id(struct InformItem* item, void* ctx){
    QSt_match_id* c = (QSt_match_id*)ctx;
    return item->requestID == c->id;
}

static bool pred_done_or_orphan(struct InformItem* item, void*){
    return item->received || (item->retries == 0 && item->missed);
}

snmp_request_id_t
queue_and_send_trap(struct InformItem **informList, int& informCount, SNMPTrap *trap, const IPAddress& ip, bool replaceQueuedRequests,
                    int retries, int delay_ms) {
    bool buildStatus = trap->buildForSending();
    if(!buildStatus) {
        SNMP_LOGW("Couldn't build trap\n");
        /* v3.3.3: _build_pdu_envelope assigns this->packet=root BEFORE filling;
         * a mid-build failure leaves a partial tree in the persistent trap
         * object — stale cross-tick pool state (the slot-12 alarm class).
         * Release it now; the trap stays stateless either way. */
        trap->releasePoolState();
        return INVALID_SNMP_REQUEST_ID;
    };
    SNMP_LOGD("%d informs in informList", informCount);
    if(replaceQueuedRequests){
        SNMP_LOGD("Removing any outstanding informs for this trap\n");
        QSt_match_trap ctx{trap};
        remove_informs_matching(informList, informCount, pred_match_trap, &ctx);
    }

    if(trap->inform){
        if(informCount >= SNMP_MAX_TRAPS_INFLIGHT){
            SNMP_LOGW("Inform queue full (%d slots), dropping request %lu\n", SNMP_MAX_TRAPS_INFLIGHT, trap->requestID);
            return INVALID_SNMP_REQUEST_ID;
        }

        struct InformItem* item = (struct InformItem*)calloc(1, sizeof(struct InformItem));
        if(!item){
            SNMP_LOGW("Couldn't calloc InformItem for request %lu\n", trap->requestID);
            return INVALID_SNMP_REQUEST_ID;
        }
        item->delay_ms = delay_ms;
        item->received = false;
        item->requestID = trap->requestID;
        item->retries = retries;
        item->ip = ip;
        item->lastSent = millis();
        item->trap = trap;
        item->missed = false;

        SNMP_LOGD("Adding Inform request to queue: %lu\n", item->requestID);

        informList[informCount++] = item;

        trap->sendTo(ip, true);
    } else {
        SNMP_LOGD("Sending normal trap\n");
        trap->sendTo(ip);
    }

    return trap->requestID;
}

void inform_callback(struct InformItem **informList, int& informCount, snmp_request_id_t requestID, bool responseReceiveSuccess) {
    (void)responseReceiveSuccess;
    SNMP_LOGD("Receiving InformCallback for requestID: %lu, success: %d\n", requestID, responseReceiveSuccess);

    QSt_match_id ctx{requestID};
    remove_informs_matching(informList, informCount, pred_match_request_id, &ctx);

    SNMP_LOGD("Informs waiting for responses: %d\n", informCount);
}

void handle_inform_queue(struct InformItem **informList, int& informCount) {
    auto thisLoop = millis();
    for(int i = 0; i < informCount; i++){
        struct InformItem* informItem = informList[i];
        if(!informItem) continue;
        if(!informItem->received && thisLoop - informItem->lastSent > (unsigned long)informItem->delay_ms){
            SNMP_LOGD("Missed Inform receive\n");
            informItem->missed = true;
            if(!informItem->retries){
                SNMP_LOGD("No more retries for inform: %lu, removing\n", informItem->requestID);
                continue;
            }
            if(informItem->trap){
                SNMP_LOGD("No response received in %dms, Resending Inform: %lu\n", informItem->delay_ms, informItem->requestID);
                informItem->trap->sendTo(informItem->ip, true);
                informItem->lastSent = thisLoop;
                informItem->missed = false;
                informItem->retries--;
            }
        }
    }
    remove_informs_matching(informList, informCount, pred_done_or_orphan, nullptr);
}

void mark_trap_deleted(struct InformItem **informList, int& informCount, SNMPTrap *trap) {
    SNMP_LOGD("Removing waiting Informs tied to Trap.\n");
    QSt_match_trap ctx{trap};
    remove_informs_matching(informList, informCount, pred_match_trap, &ctx);
}
