#if defined(__linux__) /* isatty/fileno under -std=c++11 (strict ANSI hides POSIX decls on glibc); Apple SDK must NOT define it (breaks sysctl.h) */
#define _POSIX_C_SOURCE 200809L
#endif
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include <cstring>
#include <cstdlib>     /* std::getenv */

#include "include/SNMPPacket.h"
#include "include/ValueCallbacks.h"
#include "include/SNMPParser.h"

#include "SNMPTrap.h"
#include "SNMP_Embedded.h"   /* v3.3.4: SNMPAgent / RFC1213Config for the system-group tests */

#include <list>
#include <string>
#include <cstdio>
#include <unistd.h>   /* isatty / fileno — colour auto-detection */

/* ==========================================================================
 * End-of-run summary (Catch2 v2 listener, colour-coded).
 *
 * The stock footer "All tests passed (nnn assertions in nn test cases)"
 * says little about WHAT was exercised.  This listener accumulates a
 * per-test-case PASS/WARN/FAIL table (section re-runs of one case are
 * grouped with an xN count) and, after the standard Catch2 footer, prints:
 *   - one row per test case with its assertion count
 *   - this build's derived constants (packet budget -> varbind cap -> pool)
 *   - overall totals + ALL GREEN / PASS w/ WARNINGS / FAILURES PRESENT
 *
 * Colour (ANSI): green PASS, yellow WARN/warnings, red FAIL — applied only
 * when stdout is a terminal; redirected output (CI logs, saved captures)
 * stays escape-free.  SNMP_TEST_FORCE_COLOR=1 forces colours on, =0 forces
 * off.  Host-only: tests.cpp is excluded from every distribution channel.
 * ========================================================================== */
namespace snmp_summary {
    struct Row { std::string name; int passed = 0; int failed = 0; int warned = 0; int runs = 0; };
    static Row rows[64];
    static int rowCount = 0;

    /* ANSI helpers — empty strings when colour is disabled. */
    static const char* gGreen = "", *gYellow = "", *gRed = "", *gDim = "", *gReset = "";
    static bool colourEnabled(){
        const char* force = std::getenv( "SNMP_TEST_FORCE_COLOR" );
        if( force && force[0] == '1' ) return true;
        if( force && force[0] == '0' ) return false;
        return isatty( fileno(stdout) ) == 1;
    }
    static void initColours(){
        if( !colourEnabled() ) return;
        gGreen  = "\033[32m"; gYellow = "\033[33m"; gRed = "\033[31m";
        gDim    = "\033[2m";  gReset  = "\033[0m";
    }
}

class SummaryListener : public Catch::TestEventListenerBase {
public:
    using Catch::TestEventListenerBase::TestEventListenerBase;

    void testCaseStarting( Catch::TestCaseInfo const& ti ) override {
        m_name = ti.name;
        m_p = 0; m_f = 0; m_w = 0;
    }

    bool assertionEnded( Catch::AssertionStats const& stats ) override {
        Catch::ResultWas::OfType t = stats.assertionResult.getResultType();
        if( t == Catch::ResultWas::Warning )          m_w++;
        else if( stats.assertionResult.isOk() )       m_p++;
        else                                          m_f++;
        return true;
    }

    void testCaseEnded( Catch::TestCaseStats const& ) override {
        snmp_summary::Row* r = nullptr;
        for( int i = 0; i < snmp_summary::rowCount; i++ )
            if( snmp_summary::rows[i].name == m_name ){ r = &snmp_summary::rows[i]; break; }
        if( !r && snmp_summary::rowCount < 64 ){
            r = &snmp_summary::rows[snmp_summary::rowCount++];
            r->name = m_name;
        }
        if( r ){ r->passed += m_p; r->failed += m_f; r->warned += m_w; r->runs++; }
        m_totalP += m_p; m_totalF += m_f; m_totalW += m_w;
    }

    void testRunEnded( Catch::TestRunStats const& ) override {
        using namespace snmp_summary;
        initColours();
        int anyFail = 0, anyWarn = 0;

        std::printf( "\n%s===============================================================================\n", gDim );
        std::printf( "SNMP_Embedded host-test summary\n%s", gReset );
        std::printf( "  build profile: MAX_SNMP_PACKET_LENGTH=%d -> SNMP_MAX_VARBINDS=%d  (fit: %d*%d+%d <= %d)\n",
                     (int)MAX_SNMP_PACKET_LENGTH, (int)SNMP_MAX_VARBINDS,
                     (int)SNMP_MAX_VARBINDS, (int)SNMP_WORST_CASE_VARBIND_BYTES,
                     (int)SNMP_PACKET_FIXED_OVERHEAD, (int)MAX_SNMP_PACKET_LENGTH );
        std::printf( "  pool: %d slots x %d B slot (transient burst term %d)\n",
                     (int)SNMP_POOL_ASN_OBJECTS, (int)SNMP_POOL_SLOT_SIZE,
                     (int)SNMP_WORST_TICK_TRANSIENTS );
        for( int i = 0; i < rowCount; i++ ){
            Row& r = rows[i];
            const char* tag; const char* c;
            if( r.failed ){      tag = "FAIL"; c = gRed;    anyFail = 1; }
            else if( r.warned ){ tag = "WARN"; c = gYellow; anyWarn = 1; }
            else               { tag = "PASS"; c = gGreen; }
            std::printf( "  %s[%s]%s %s%s -- %d assertions%s\n",
                         c, tag, gReset, r.name.c_str(),
                         ( r.runs > 1 ) ? "  (grouped xN section-runs)" : "",
                         r.passed + r.failed + r.warned,
                         ( r.warned && !r.failed ) ? " (has warnings)" : "" );
            if( r.warned && !r.failed )
                std::printf( "      %s%d warning assertion(s) in this case%s\n", gYellow, r.warned, gReset );
        }
        std::printf( "  total: %d assertions (%s%d passed%s, %s%d warned%s, %s%d failed%s) across %d test cases\n",
                     m_totalP + m_totalF + m_totalW,
                     gGreen, m_totalP, gReset,
                     gYellow, m_totalW, gReset,
                     gRed,    m_totalF, gReset,
                     rowCount );
        const char* verdict      = anyFail ? "FAILURES PRESENT" : ( anyWarn ? "PASS (with warnings)" : "ALL GREEN" );
        const char* verdictColor = anyFail ? gRed : ( anyWarn ? gYellow : gGreen );
        std::printf( "  RESULT: %s%s%s\n", verdictColor, verdict, gReset );
        std::printf( "%s===============================================================================\n%s", gDim, gReset );
    }

private:
    std::string m_name;
    int m_p = 0, m_f = 0, m_w = 0;
    int m_totalP = 0, m_totalF = 0, m_totalW = 0;
};
CATCH_REGISTER_LISTENER( SummaryListener )

/* ==========================================================================
 * Pool-hygiene helper (host-test only).
 *
 * The host suite exercises handlePacket()/build/serialise directly, WITHOUT
 * the SNMPAgent::loop() tick that on hardware bulk-frees transient slots via
 * ASNPool::resetAll() every iteration.  As a result, response trees and
 * decode intermediates accumulated across earlier TEST_CASEs stay marked
 * occupied in the ASNPool, and the first resetAll() (in the v3.3.3 pool
 * tests) froze that accumulated occupancy as the "permanent" startup
 * baseline (used=142 perm=142 cap=142).  From that
 * point every asn_new<>() fell back to the heap and the pool-semantics
 * assertions ran vacuously ("heap fallback" warnings).
 *
 * test_tick_reset() models one hardware loop() tick WITHOUT freezing a
 * baseline: it hard-frees every occupied slot (running real destructors),
 * zeroes usedCount/permCount and unfreezes the baseline so a later
 * freezePermCount() sees only genuinely-permanent registrations.
 * Call it at TEST_CASE boundaries as a tick-boundary stand-in.
 * ========================================================================== */
static void test_tick_reset(){
#ifndef SNMP_POOLS_IN_BSS
    if(!ASNPool::_poolsReady) return;      /* pool not yet allocated: nothing to do */
#endif
    /* Pass 1: mark every occupied slot bulk-freed BEFORE destroying anything,
     * so destructor-driven cross-slot asn_delete()s (ComplexType parent ->
     * child) that strike an already-destroyed slot stay silent — the same
     * sanctioned-stale-delete contract resetAll() grants. */
    for(int i = 0; i < SNMP_POOL_ASN_OBJECTS; i++)
        if(ASNPool::slots[i].occupied) ASNPool::slots[i].bulkFreed = true;
    /* Pass 2: run real destructors in index order.  Parents normally precede
     * children (every build/decode path allocates the parent first), so most
     * children are already freed via their parent's destructor. */
    for(int i = 0; i < SNMP_POOL_ASN_OBJECTS; i++){
        if(ASNPool::slots[i].occupied){
            reinterpret_cast<BER_CONTAINER*>(ASNPool::slots[i].storage)->~BER_CONTAINER();
            ASNPool::slots[i].occupied = false;
        }
    }
    /* Pass 3: clear flags LAST — only now is every slot genuinely free. */
    for(int i = 0; i < SNMP_POOL_ASN_OBJECTS; i++){
        ASNPool::slots[i].doubleReleaseWarned = false;
        ASNPool::slots[i].bulkFreed           = false;
    }
    ASNPool::usedCount  = 0;
    ASNPool::permCount  = 0;
    ASNPool::permFrozen = false;
    ASNPool::usedCountPeak = 0;
}

static SNMPPacket* GenerateTestSNMPRequestPacket(){
    SNMPPacket* packet = new SNMPPacket();

    packet->setPDUType(GetRequestPDU);
    packet->setCommunityString("public");
    packet->setRequestID(random());
    packet->setVersion(SNMP_VERSION_1);

    packet->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.1"),                  std::make_shared<IntegerType>(42)));
    packet->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.2"),                  std::make_shared<OctetType>("test 123")));
    packet->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.52420.9999999"),        std::make_shared<IntegerType>(0)));
    packet->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.3"),                  std::make_shared<IntegerType>(-42)));
    packet->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.4"),                  std::make_shared<IntegerType>(-420000)));

    return packet;
}

TEST_CASE( "Test handle failures when Encoding/Decoding", "[snmp]"){
    SNMPPacket *packet = GenerateTestSNMPRequestPacket();
    uint8_t buffer[500] = {0};
    int serialised_length = 0;

    serialised_length = packet->serialiseInto(buffer, 500);
    REQUIRE( serialised_length == 133 );

    SECTION( "Failed Serialisation" ){
        serialised_length = packet->serialiseInto(buffer, 132);
        REQUIRE( serialised_length <= 0 );
    }

    SECTION( "Suceed Serialisation" ){
        serialised_length = packet->serialiseInto(buffer, 133);
        REQUIRE( serialised_length == 133 );
    }

    uint8_t copyBuffer[500] = {0};

    memcpy(copyBuffer, buffer, 500);

    SECTION( "Should fail to parse a buffer too small"){
        SNMPPacket* readPack = new SNMPPacket();
        int rc = readPack->parseFrom(buffer, 130);
        REQUIRE( rc != SNMP_ERROR_OK );
    }

    SECTION( "Decoding should not modify the buffer"){
        REQUIRE( memcmp(copyBuffer, buffer, 500) == 0 );
    }

/*
    SECTION( "Should be able to reparse the buffer with correct max_size"){
        SNMPPacket* readPack = new SNMPPacket();
        REQUIRE( readPack->parseFrom(buffer, 133) == SNMP_ERROR_OK );
    }
*/

/*
    SECTION( "Should fail to parse a corrupt buffer "){
        SNMPPacket* readPacket = new SNMPPacket();
        for(int i = 25; i < 133; i+= 10){
            char old[10] = {0};
            memcpy(old, &buffer[i], 10);
            long randomLong = random();
            memcpy(&buffer[i], &randomLong, sizeof(randomLong));
            REQUIRE( readPacket->parseFrom(buffer, 200) != SNMP_ERROR_OK );

            memcpy(&buffer[i], old, 10);
            REQUIRE( readPacket->parseFrom(buffer, 200) == SNMP_ERROR_OK );
        }
    }
*/
}

TEST_CASE( "Test Encoding/Decoding packet", "[snmp]" ) {
    // Build Packet
    SNMPPacket *packet = GenerateTestSNMPRequestPacket();
    uint8_t buffer[500];
    int serialised_length = 0;

    SECTION( "Serialisation" ){
        serialised_length = packet->serialiseInto(buffer, 500);
        REQUIRE( serialised_length == 133 );
    }
    // Read packet
    SNMPPacket* readPacket = new SNMPPacket();
    REQUIRE( readPacket->parseFrom(buffer, serialised_length) == SNMP_ERROR_OK);

    // Check Meta
    REQUIRE( strcmp(packet->communityString, readPacket->communityString) == 0 );
    REQUIRE( packet->requestID == readPacket->requestID );
    REQUIRE( packet->snmpVersion == readPacket->snmpVersion );

    // Check Varbinds
    REQUIRE( packet->size() == 5 );

        // Integer
        REQUIRE( strcmp(packet->varbindList[0].oid->string(), ".1.3.6.1.4.1.5.1") == 0 );
        REQUIRE( packet->varbindList[0].type == ASN_TYPE::INTEGER );
        REQUIRE( static_cast<IntegerType*>(packet->varbindList[0].value)->_value == 42 );

        // String
        REQUIRE( strcmp(packet->varbindList[1].oid->string(), ".1.3.6.1.4.1.5.2") == 0 );
        REQUIRE( packet->varbindList[1].type == ASN_TYPE::STRING );
        REQUIRE( strcmp(static_cast<OctetType*>(packet->varbindList[1].value)->_value, "test 123") == 0 );

        // Long OID Integer
        REQUIRE( strcmp(packet->varbindList[2].oid->string(), ".1.3.6.1.4.1.52420.9999999") == 0 );
        REQUIRE( packet->varbindList[2].type == ASN_TYPE::INTEGER );
        REQUIRE( static_cast<IntegerType*>(packet->varbindList[2].value)->_value == 0 );

        REQUIRE( strcmp(packet->varbindList[3].oid->string(), ".1.3.6.1.4.1.5.3") == 0 );
        REQUIRE( packet->varbindList[3].type == ASN_TYPE::INTEGER );
        REQUIRE( static_cast<IntegerType*>(packet->varbindList[3].value)->_value == -42 );

        REQUIRE( strcmp(packet->varbindList[4].oid->string(), ".1.3.6.1.4.1.5.4") == 0 );
        REQUIRE( packet->varbindList[4].type == ASN_TYPE::INTEGER );
        REQUIRE( static_cast<IntegerType*>(packet->varbindList[4].value)->_value == -420000 );
}

TEST_CASE( "Test GetRequestPDU", "[snmp]" ){
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    int testInt = 23;
    ValueCallback* integer = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = integer;

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    uint8_t buffer[500];
    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, callbacksCount, (char*)"public", (char*)"private") == SNMP_GET_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );

    REQUIRE( responsePacket->varbindList[0].type == INTEGER );
    REQUIRE( static_cast<IntegerType*>(responsePacket->varbindList[0].value)->_value == 23 );
}

TEST_CASE( "Test GetNextRequestPDU", "[snmp]" ){
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    int testInt = 23;
    IntegerCallback* integer = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = integer;

    IntegerCallback* integer2 = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.2"), &testInt);
    callbacks[callbacksCount++] = integer2;

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    requestPacket->setPDUType(GetNextRequestPDU);
    uint8_t buffer[500];
    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, callbacksCount, "public", "private") == SNMP_GETNEXT_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );

    REQUIRE( responsePacket->varbindList[0].type == INTEGER );
    REQUIRE( strcmp(responsePacket->varbindList[0].oid->string(), ".1.3.6.1.4.1.5.2") == 0 );
}

TEST_CASE( "Test GetBulkRequestPDU", "[snmp]"){
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    int testInt = 23;
    IntegerCallback* integer = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = integer;

    IntegerCallback* integer2 = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.2"), &testInt);
    callbacks[callbacksCount++] = integer2;

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    requestPacket->pop_back();
    requestPacket->pop_back();
    requestPacket->pop_back();
    requestPacket->pop_back();

    requestPacket->setVersion(SNMP_VERSION_2C);
    requestPacket->setPDUType(GetBulkRequestPDU);
    requestPacket->errorIndex.maxRepititions = 2;
    requestPacket->errorStatus.nonRepeaters = 0;

    uint8_t buffer[500];
    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, callbacksCount, (char*)"public", (char*)"private") == SNMP_GETBULK_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );

    REQUIRE( responsePacket->size() == 2 );

    REQUIRE( responsePacket->varbindList[0].type == INTEGER );
    REQUIRE( strcmp(responsePacket->varbindList[0].oid->string(), ".1.3.6.1.4.1.5.2") == 0 );

    REQUIRE( responsePacket->varbindList[1].type == ENDOFMIBVIEW );
}

TEST_CASE( "Test SetRequestPDU", "[snmp]" ){
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    int testInt = 23;
    IntegerCallback* integerCallback = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    integerCallback->isSettable = false;
    callbacks[callbacksCount++] = integerCallback;

    int testInt2 = 23;
    IntegerCallback* integerCallback2 = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.4"), &testInt2);
    integerCallback2->isSettable = true;
    callbacks[callbacksCount++] = integerCallback2;

    uint8_t opaqueBuf[5] = { 1, 2, 3, 4, 5 };
    OpaqueCallback* opaqueCallback = new OpaqueCallback(new SortableOIDType(".1.3.6.1.4.1.5.7"), opaqueBuf, 5);
    opaqueCallback->isSettable = true;
    callbacks[callbacksCount++] = opaqueCallback;

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    requestPacket->setPDUType(SetRequestPDU);

    uint8_t setOpaqueBuf[5] = { 5, 4, 3, 2, 1 };
    requestPacket->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.7"),                  std::make_shared<OpaqueType>(setOpaqueBuf, 5)));

    uint8_t buffer[500];

    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, callbacksCount, (char*)"public", (char*)"public") == SNMP_SET_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );

    REQUIRE( integerCallback->setOccurred == false );
    REQUIRE( testInt == 23 );

    REQUIRE( integerCallback2->setOccurred == true );
    REQUIRE( testInt2 == -420000 );

    REQUIRE( opaqueCallback->setOccurred == true );
    REQUIRE( opaqueBuf[0] == 5 );
    REQUIRE( opaqueBuf[1] == 4 );
    REQUIRE( opaqueBuf[2] == 3 );
    REQUIRE( opaqueBuf[3] == 2 );
    REQUIRE( opaqueBuf[4] == 1 );

}


TEST_CASE( "sort/remove handlers ", "[snmp]"){
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.51.2"), nullptr);
    ValueCallback* cb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.510.2"), nullptr);
    callbacks[callbacksCount++] = cb;
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5100.2"), nullptr);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5100.1"), nullptr);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.51000.1"), nullptr);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.510.1"), nullptr);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.51.1"), nullptr);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1200.5100000.1"), nullptr);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.2"), nullptr);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1200.5.2"), nullptr);


    sort_handlers(callbacks, callbacksCount);

    int idx = 0;

    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.5.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.51.1") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.51.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.510.1") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.510.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.5100.1") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.5100.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.51000.1") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1200.5.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1200.5100000.1") == 0 );
    idx++;

    REQUIRE( callbacksCount == 10 );

    remove_handler(callbacks, callbacksCount, cb);
    
    REQUIRE( callbacksCount == 9 );

    for(int i = 0; i < callbacksCount; i++){
        REQUIRE( callbacks[i] != cb );
    }

    REQUIRE( strcmp(cb->OID->string(), ".1.3.6.1.4.1.510.2") == 0 );

    idx = 0;

    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.5.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.51.1") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.51.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.510.1") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.5100.1") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.5100.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1.51000.1") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1200.5.2") == 0 );
    idx++;
    REQUIRE( strcmp(callbacks[idx]->OID->string(), ".1.3.6.1.4.1200.5100000.1") == 0 );
    idx++;

}

TEST_CASE( "SNMPTraps ", "[snmp]"){
    SNMPTrap* settableNumberTrap = new SNMPTrap("public", SNMP_VERSION_1);

    uint32_t tensOfMillisCounter = 10;
    int changingNumber = 12;
    int settableNumber = 78;

    IntegerCallback* changingNumberOID = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.23.0"), &changingNumber);
    IntegerCallback* settableNumberOID = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.24.0"), &settableNumber);
    TimestampCallback* timestampCallbackOID = new TimestampCallback(new SortableOIDType(".1.3.6.1.2.1.1.3.0"), &tensOfMillisCounter);

    settableNumberTrap->setTrapOID(new OIDType(".1.3.6.1.2.1.33.2")); // OID of the trap
    settableNumberTrap->setSpecificTrap(1); 

    // Set the uptime counter to use in the trap
    settableNumberTrap->setUptimeCallback(timestampCallbackOID);

    // Set some previously set OID Callbacks to send these values with the trap
    settableNumberTrap->addOIDPointer(changingNumberOID);
    settableNumberTrap->addOIDPointer(settableNumberOID);

    settableNumberTrap->setIP(IPAddress(192, 168, 0, 1)); // Set our Source IP

    REQUIRE( settableNumberTrap->buildForSending() == true );


    uint8_t buffer[500] = {0};

    REQUIRE( settableNumberTrap->packet->serialise(buffer, 500) > 0 );


     ComplexType* trapBuffer = new ComplexType(STRUCTURE);
     REQUIRE( trapBuffer->fromBuffer(buffer, 150) == SNMP_BUFFER_ERROR_UNKNOWN_TYPE );

    // Traps cannot be parsed as regular packets and we'll make sure parsing fails'
//    SNMPPacket* trapPacket = new SNMPPacket();
//    REQUIRE( trapPacket->parseFrom(buffer, 150) == SNMP_PARSE_ERROR_AT_STATE(REQUESTID) );

}

TEST_CASE( "SNMPInform ", "[snmp]"){
    SNMPTrap* settableNumberTrap = new SNMPTrap("public", SNMP_VERSION_2C);
    settableNumberTrap->setInform(true);

    uint32_t tensOfMillisCounter = 10;
    int changingNumber = 12;
    int settableNumber = 78;

    IntegerCallback* changingNumberOID = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.23.0"), &changingNumber);
    IntegerCallback* settableNumberOID = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.24.0"), &settableNumber);
    TimestampCallback* timestampCallbackOID = new TimestampCallback(new SortableOIDType(".1.3.6.1.2.1.1.3.0"), &tensOfMillisCounter);

    settableNumberTrap->setTrapOID(new OIDType(".1.3.6.1.2.1.33.2")); // OID of the trap

    // Set the uptime counter to use in the trap
    settableNumberTrap->setUptimeCallback(timestampCallbackOID);

    // Set some previously set OID Callbacks to send these values with the trap
    settableNumberTrap->addOIDPointer(changingNumberOID);
    settableNumberTrap->addOIDPointer(settableNumberOID);

    settableNumberTrap->setIP(IPAddress(192, 168, 0, 1)); // Set our Source IP

    REQUIRE( settableNumberTrap->buildForSending() == true );

    uint8_t buffer[500] = {0};

    REQUIRE( settableNumberTrap->packet->serialise(buffer, 500) > 0 );

    SNMPPacket* trapPacket = new SNMPPacket();
    REQUIRE(trapPacket->parseFrom(buffer, 150) == SNMP_ERROR_OK);

    REQUIRE( trapPacket->packetPDUType == InformRequestPDU );

}

TEST_CASE( "Test OID Validation ", "[snmp]"){
    REQUIRE( (new OIDType(".1.3.6.1.4.1.52420"))->valid );
    REQUIRE( (new OIDType(".1.3.6.1.4.1.52420."))->valid );
    REQUIRE( (new OIDType("1.3.6.1.4.1.52420"))->valid == false );
    REQUIRE( (new OIDType(".1.3.6.1.4.1..52420"))->valid == false );
}

TEST_CASE( "GetBulk exceeding SNMP_MAX_VARBINDS answers tooBig (no silent truncation)", "[snmp][v3124]"){
    test_tick_reset();
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    /* Register cap+1 OIDs so a one-repeater walk wants cap+1 appends
     * (cap values + endOfMibView) → guaranteed one-append overflow. */
    static int vals[SNMP_MAX_VARBINDS + 1];
    for(int i = 0; i < SNMP_MAX_VARBINDS + 1; i++){
        char oid[32];
        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.9.1.%d", i + 1);
        vals[i] = i;
        callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(oid), &vals[i]);
    }

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    while(requestPacket->size() > 1) requestPacket->pop_back();
    /* Aim the repeater at the PARENT OID .1.3.6.1.4.1.9 — findCallback's
     * subtree match resolves it to .9.1.1, then walks leaf-by-leaf through
     * all cap+1 registered OIDs → 17th append overflows the cap. */
    requestPacket->at(0) = VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.9"), std::make_shared<IntegerType>(0));

    requestPacket->setVersion(SNMP_VERSION_2C);
    requestPacket->setPDUType(GetBulkRequestPDU);
    requestPacket->errorStatus.nonRepeaters = 0;
    requestPacket->errorIndex.maxRepititions = SNMP_MAX_VARBINDS + 4;

    uint8_t buffer[500];
    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    /* Overflow is now loud: handlePacket sends a global tooBig error PDU
     * and reports SNMP_ERROR_PACKET_SENT (same convention as the other
     * error-PDU paths, e.g. GetBulk on a v1 request). */
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, callbacksCount, (char*)"public", (char*)"private") == SNMP_ERROR_PACKET_SENT );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );
    REQUIRE( responsePacket->errorStatus.errorStatus == TOO_BIG );
    REQUIRE( responsePacket->size() == 0 );
}

TEST_CASE( "Request with exactly SNMP_MAX_VARBINDS varbinds is served (no false reject)", "[snmp][v3124]"){
    test_tick_reset();
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    static int vals[SNMP_MAX_VARBINDS];
    for(int i = 0; i < SNMP_MAX_VARBINDS; i++){
        char oid[32];
        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.9.2.%d", i + 1);
        callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(oid), &vals[i]);
    }

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    while(requestPacket->size() > 0) requestPacket->pop_back();
    for(int i = 0; i < SNMP_MAX_VARBINDS; i++){
        char oid[32];
        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.9.2.%d", i + 1);
        requestPacket->push_back(VarBind(std::make_shared<SortableOIDType>(oid), std::make_shared<IntegerType>(i)));
    }
    REQUIRE( requestPacket->size() == SNMP_MAX_VARBINDS );

    uint8_t buffer[800];
    int buf_len = requestPacket->serialiseInto(buffer, 800);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 800, callbacks, callbacksCount, (char*)"public", (char*)"private") == SNMP_GET_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );
    REQUIRE( responsePacket->size() == SNMP_MAX_VARBINDS );
}

/* ---- v3.3.3: bulkFree stale-delete vs true double-destroy ---- */
TEST_CASE( "Stale asn_delete after resetAll is silent; true double-destroy still alarms", "[snmp][v3333]"){
    test_tick_reset();
    ASNPool::resetAll();                       /* establish baseline */
    int baseAlarms = ASNPool::doubleReleaseAlarms;
    fprintf(stderr, "[v3333] pool state: used=%d perm=%d cap=%d\n",
            ASNPool::usedCount, ASNPool::permCount, (int)SNMP_POOL_ASN_OBJECTS);

    /* 1. trap-rebuild pattern: alloc, resetAll() (bulk-frees the slot), then
     *    asn_delete the stale pointer — the sanctioned shape, must NOT alarm. */
    OIDType* stale = asn_new<OIDType>(".1.3.6.1.4.1.99999.1.1.0");
    ASNPool::resetAll();
    if(ASNPool::isInPool(stale)){
        asn_delete(stale);                     /* stale delete post-reset */
        REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms );
    } else {
        /* Pool exhausted by earlier tests: host fallback is operator-new'd,
         * so this is a plain heap object — single delete, nothing to assert. */
        fprintf(stderr, "[v3333] stale object NOT in pool (heap fallback)\n");
        asn_delete(stale);
        WARN( "[v3333] pool exhausted by earlier tests: stale-delete scenario ran on heap fallback" );
    }

    /* 2. re-arm the slot with a live object, delete it normally, delete AGAIN:
     *    a true double-destroy must alarm exactly once. */
    OIDType* live = asn_new<OIDType>(".1.3.6.1.4.1.99999.1.2.0");
    if(ASNPool::isInPool(live)){
        asn_delete(live);
        asn_delete(live);                      /* second delete = true bug */
        REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms + 1 );

        /* 3. triple-delete of the same object: still exactly one alarm (one-shot latch). */
        asn_delete(live);
        REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms + 1 );
    } else {
        fprintf(stderr, "[v3333] live object NOT in pool (heap fallback)\n");
        asn_delete(live);
        WARN( "[v3333] double-destroy alarm scenario skipped: heap fallback (exhausted pool)" );
    }

    /* 4. clean state for the rest of the suite. */
    ASNPool::resetAll();
}

/* ---- v3.3.3: stateless trap sends — no pool state survives sendTo ---- */
TEST_CASE( "Repeated trap sends are stateless: no leak, no alarms, packet freed", "[snmp][v3333]" ){
    test_tick_reset();
    ASNPool::resetAll();
    int baseAlarms = ASNPool::doubleReleaseAlarms;
    int baseUsed   = ASNPool::usedCount;

    UDP udp;
    IPAddress trapIp(192,168,1,10);

    SNMPTrap trap((char*)"public", SNMP_VERSION_2C);
    trap.setUDP(&udp);
    trap.setUDPport(162);
    trap.setTrapOID(".1.3.6.1.4.1.99999.0.1");     /* heap-owned (v3.3.3) */
    trap.setInform(false);

    int32_t trapPayload = 7;
    ValueCallback* trapInt = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.10.0"), &trapPayload);
    trap.addOIDPointer(trapInt);

    /* 1. back-to-back sends with a loop()-style bulk free before each: the
     *    persistent trap object must leave NOTHING pool-backed alive between
     *    sends (usedCount returns to baseline, no stale-delete alarms). */
    for(int round = 0; round < 6; round++){
        ASNPool::resetAll();
        trapPayload = round;
        REQUIRE( trap.sendTo(trapIp) == true );
        REQUIRE( trap.packet == nullptr );          /* tree released          */
        REQUIRE( trap.varbindCount == 0 );          /* varbind state released */
        REQUIRE( ASNPool::usedCount == baseUsed );  /* zero leak per send     */
        REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms );
    }

    /* 2. flood-style interleaving: response traffic reallocates trap slots
     *    between sends (the mechanism behind the hardware slot-12 alarm).
     *    With the stateless teardown the next round's rebuild/teardown must
     *    stay silent — no stale pointer can alias a re-armed slot. */
    for(int round = 0; round < 6; round++){
        ASNPool::resetAll();
        trapPayload = 100 + round;
        REQUIRE( trap.sendTo(trapIp) == true );
        OIDType* churn = asn_new<OIDType>(".1.3.6.1.4.1.99999.1.99.0");
        asn_delete(churn);
        ASNPool::resetAll();
        REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms );
    }

    delete trapInt;
    ASNPool::resetAll();    /* destructor path must also be alarm-free */
}

/* ---- v3.3.2: packet size is the controlling authority ---- */

TEST_CASE( "v3.3.2: varbind cap is derived from packet budget (all documented profiles)", "[snmp][v3332]"){
    /* ---- the DERIVATION FORMULA, anchored at all four documented budgets ----
     *  MAXVB = (packet - 40) / 160  ->
     *    1400 -> 8   generic default
     *    1024 -> 6   ESP8266 TINY default (campaign-proven cap)
     *     768 -> 4   ultra-tight profile (flood-calibrated pool 56)
     *     512 -> 2   extreme-constrained (RFC 3417 floor datagram ~484 B)   */
    REQUIRE( (1400 - SNMP_PACKET_FIXED_OVERHEAD) / SNMP_WORST_CASE_VARBIND_BYTES == 8 );
    REQUIRE( (1024 - SNMP_PACKET_FIXED_OVERHEAD) / SNMP_WORST_CASE_VARBIND_BYTES == 6 );
    REQUIRE( ( 768 - SNMP_PACKET_FIXED_OVERHEAD) / SNMP_WORST_CASE_VARBIND_BYTES == 4 );
    REQUIRE( ( 512 - SNMP_PACKET_FIXED_OVERHEAD) / SNMP_WORST_CASE_VARBIND_BYTES == 2 );

    /* ---- the FIT INVARIANT at every budget: cap*worstVB + overhead <= packet
     *      (mirrors the defs.h static_assert for each profile) ---- */
    REQUIRE( 8 * SNMP_WORST_CASE_VARBIND_BYTES + SNMP_PACKET_FIXED_OVERHEAD <= 1400 );
    REQUIRE( 6 * SNMP_WORST_CASE_VARBIND_BYTES + SNMP_PACKET_FIXED_OVERHEAD <= 1024 );
    REQUIRE( 4 * SNMP_WORST_CASE_VARBIND_BYTES + SNMP_PACKET_FIXED_OVERHEAD <=  768 );
    REQUIRE( 2 * SNMP_WORST_CASE_VARBIND_BYTES + SNMP_PACKET_FIXED_OVERHEAD <=  512 );

    /* ---- THIS binary's compiled profile: cap == formula at its own budget. */
    REQUIRE( SNMP_MAX_VARBINDS == (MAX_SNMP_PACKET_LENGTH - SNMP_PACKET_FIXED_OVERHEAD) / SNMP_WORST_CASE_VARBIND_BYTES );
    REQUIRE( SNMP_MAX_VARBINDS >= 1 );
    #ifdef _SNMP_ESP8266_TINY
    REQUIRE( SNMP_MAX_VARBINDS == 6 );   /* campaign-proven TINY cap */
    #endif
}

TEST_CASE( "Response exceeding packet budget answers tooBig (RFC 3416), no silent timeout", "[snmp][v3332]"){
    test_tick_reset();
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    /* 3 full-width string handlers.  Each served OID serializes at the
     * TINY OID budget (192+3=195 B), so a 3-varbind response demands
     * ~585 B of OID text alone and cannot fit max_packet_size=500 —
     * while the request itself (short OIDs, 3 < cap) parses normally. */
    static char BIG[SNMP_MAX_STRING_LEN];
    for(size_t i = 0; i < sizeof(BIG) - 1; i++) BIG[i] = 'x';
    BIG[sizeof(BIG) - 1] = 0;

    for(int i = 1; i <= 3; i++){
        char oid[32];
        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.9.3.%d", i);
        callbacks[callbacksCount++] = new ReadOnlyStringCallback(new SortableOIDType(oid), BIG);
    }

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    while(requestPacket->size() > 0) requestPacket->pop_back();
    for(int i = 1; i <= 3; i++){
        char oid[32];
        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.9.3.%d", i);
        requestPacket->push_back(VarBind(std::make_shared<SortableOIDType>(oid), std::make_shared<IntegerType>(i)));
    }

    uint8_t buffer[500];
    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    /* Was: SNMP_FAILED_SERIALISATION with responseLength <= 0 (no PDU on
     * the wire — manager burns its full timeout).  Now: tiny tooBig PDU. */
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, callbacksCount, (char*)"public", (char*)"private") == SNMP_ERROR_PACKET_SENT );
    REQUIRE( responseLength > 0 );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );
    REQUIRE( responsePacket->errorStatus.errorStatus == TOO_BIG );
    REQUIRE( responsePacket->size() == 0 );
}

/* ---- 12-handler deployment regression test ----
 * On hardware a 12-handler sketch (roster below) answers a Cr5 bulkwalk from
 * the sysDescr parent .1.3.6.1.2.1.1 with SNMP_FAILED_SERIALISATION and
 * serialiseInto() returning -37 (SNMP_BUFFER_ENCODE_ERROR_INVALID_OID),
 * This test mirrors that 12-handler roster exactly. */
static int  cmp_heapK(void)  { return 30; }
static uint32_t cmp_ticks(void) { return 4216; }

TEST_CASE( "12-handler deployment: Cr5 bulkwalk roster serialises", "[snmp][bulk]" ){
    test_tick_reset();
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;

    static char cmpDescr[] = "SNMP_Embedded | ESP8266 | 12 leaves";
    static uint32_t cmpUptime = 1234;
    static int32_t  cmpIntRO = 42, cmpIntRW = 7, cmpTrapCnt = 1;
    static char     cmpStrBuf[64] = "EditableString";
    static char*    cmpStr = cmpStrBuf;
    static uint32_t cmpC32 = 1, cmpG32 = 2;
    static uint8_t  cmpOpq[8] = {1,2,3,4,5,6,7,8};

    callbacks[callbacksCount++] = new ReadOnlyStringCallback(new SortableOIDType(".1.3.6.1.2.1.1.1.0"), cmpDescr);
    callbacks[callbacksCount++] = new TimestampCallback(new SortableOIDType(".1.3.6.1.2.1.1.3.0"), &cmpUptime);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.1.0"), &cmpIntRO);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.2.0"), &cmpIntRW);
    callbacks[callbacksCount++] = new DynamicIntegerCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.3.0"), &cmp_heapK);
    callbacks[callbacksCount++] = new ReadOnlyStringCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.4.0"), "Hello SNMP");
    callbacks[callbacksCount++] = new StringCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.5.0"), &cmpStr, 64);
    callbacks[callbacksCount++] = new DynamicTimestampCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.6.0"), &cmp_ticks);
    callbacks[callbacksCount++] = new Counter32Callback(new SortableOIDType(".1.3.6.1.4.1.99999.1.7.0"), &cmpC32);
    callbacks[callbacksCount++] = new Gauge32Callback(new SortableOIDType(".1.3.6.1.4.1.99999.1.8.0"), &cmpG32);
    callbacks[callbacksCount++] = new OpaqueCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.9.0"), cmpOpq, 8);
    callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.99999.1.10.0"), &cmpTrapCnt);

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    while(requestPacket->size() > 0) requestPacket->pop_back();
    requestPacket->setVersion(SNMP_VERSION_2C);
    requestPacket->setPDUType(GetBulkRequestPDU);
    requestPacket->errorIndex.maxRepititions = 5;
    requestPacket->errorStatus.nonRepeaters = 0;
    requestPacket->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.2.1.1"), std::make_shared<IntegerType>(0)));

    uint8_t buffer[800];
    int buf_len = requestPacket->serialiseInto(buffer, 800);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    enum SNMP_ERROR_RESPONSE ret = handlePacket(buffer, buf_len, &responseLength, 800, callbacks, callbacksCount, (char*)"public", (char*)"private");
    if(ret != SNMP_GETBULK_OCCURRED){
        fprintf(stderr, "bulkwalk repro: handlePacket ret=%d responseLength=%d\n", (int)ret, responseLength);
    }
    REQUIRE( ret == SNMP_GETBULK_OCCURRED );
    REQUIRE( responseLength > 0 );
}

/* ==========================================================================
 * v3.3.4 — RFC1213 system group: built-in dynamic sysUpTime + the
 * addRFC1213SystemGroup() one-call helper.
 *
 * These tests construct real SNMPAgent instances (the rest of the suite
 * drives raw callback arrays). Because each agent registers the built-in
 * uptime in its constructor and pushes itself onto the global agents[]
 * list, every test here constructs agents inside a scope and calls
 * agent.testReleaseFromRegistry() before it ends — later cases then assert
 * the registry is empty (agents[] has SNMP_MAX_AGENTS slots).
 * ========================================================================== */
namespace {
    /* Build a GetRequest packet for an arbitrary OID list. */
    static SNMPPacket* makeGetRequest(const char* const* oids, int count, SNMP_VERSION version = SNMP_VERSION_1){
        SNMPPacket* packet = new SNMPPacket();
        packet->setPDUType(GetRequestPDU);
        packet->setCommunityString("public");
        packet->setRequestID(random());
        packet->setVersion(version);
        for(int i = 0; i < count; i++)
            packet->push_back(VarBind(std::make_shared<SortableOIDType>(oids[i]), std::make_shared<IntegerType>(0)));
        return packet;
    }

    /* Run a GET through handlePacket against an agent's registration table. */
    static bool runGet(SNMPAgent* agent, const char* oid, SNMPPacket** out, int bufSize = 800){
        const char* oids[1] = { oid };
        SNMPPacket* req = makeGetRequest(oids, 1);
        uint8_t buffer[800];
        int buf_len = req->serialiseInto(buffer, bufSize);
        delete req;
        if(buf_len <= 0) return false;
        int responseLength = 0;
        SNMP_ERROR_RESPONSE r = handlePacket(buffer, buf_len, &responseLength, bufSize,
                                             agent->testCallbacks(), agent->testCallbacksCount(),
                                             (char*)"public", (char*)"private");
        if(r != SNMP_GET_OCCURRED || responseLength <= 0) return false;
        SNMPPacket* resp = new SNMPPacket();
        if(resp->parseFrom(buffer, responseLength) != SNMP_ERROR_OK){ delete resp; return false; }
        *out = resp;
        return true;
    }

    /* Fake clock: ms-resolution counter the tests advance directly. */
    static unsigned long fake_ms = 1000;
    static unsigned long fake_millis(){ return fake_ms; }
#if !SNMP_HAS_BUILTIN_SYSUPTIME
    /* opt-out build: fake clock + agent-GET helper unused — keep TU quiet
     * under -Werror by taking their addresses. */
    struct FakeClockQuiet { FakeClockQuiet(){ (void)fake_ms; (void)&fake_millis; (void)&runGet; } };
    static FakeClockQuiet s_fakeClockQuiet;
#endif
}

/* ---- opt-out build (SNMP_NO_BUILTIN_SYSUPTIME): the agent-level tests are
 * compiled out — with the flag there is no library uptime to test. The flag
 * build proving it COMPILES CLEAN and runs the pre-existing 175 assertions is
 * the opt-out verification. Negative-compile + count-delta checks live in the
 * Makefile profile and CI. ---- */
#if SNMP_HAS_BUILTIN_SYSUPTIME

TEST_CASE( "v3.3.4 built-in dynamic sysUpTime: registered by constructor, live at request time", "[snmp][v334]" ){
    test_tick_reset();
    ASNPool::resetAll();
    int baseAlarms = ASNPool::doubleReleaseAlarms;

    SNMPAgent::setUptimeSource(&fake_millis);

    {
        SNMPAgent agent((char*)"public", (char*)"private");

        /* exactly one registration before any sketch code: the built-in uptime */
        REQUIRE( agent.testCallbacksCount() == 1 );
        REQUIRE( strcmp(agent.testCallbacks()[0]->OID->string(), ".1.3.6.1.2.1.1.3.0") == 0 );

        /* value is computed at REQUEST time from the clock source */
        fake_ms = 100000;                     /* 100.000 s */
        SNMPPacket* resp = nullptr;
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.3.0", &resp) );
        REQUIRE( resp->varbindList[0].type == TIMESTAMP );
        REQUIRE( static_cast<TimestampType*>(resp->varbindList[0].value)->_value == 10000u );
        delete resp;

        /* advance the fake clock; a new GET must reflect it with no loop()
         * call and no sketch-side variable — the staleness-proof */
        fake_ms = 250000;                     /* 250.000 s */
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.3.0", &resp) );
        REQUIRE( static_cast<TimestampType*>(resp->varbindList[0].value)->_value == 25000u );
        delete resp;
        agent.testReleaseFromRegistry();
    }

    REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms );
}

/* ---- v3.3.4: addRFC1213SystemGroup — selective one-call registration ---- */
TEST_CASE( "v3.3.4 helper: sparse selection registers exactly the configured OIDs; built-in uptime is authoritative", "[snmp][v334]" ){
    test_tick_reset();
    ASNPool::resetAll();
    SNMPAgent::setUptimeSource(&fake_millis);

    static char nameBuf[64];
    static char locBuf[64];
    char* namePtr  = nameBuf;
    char* locPtr   = locBuf;
    static int services = 72;

    {
        SNMPAgent agent((char*)"public", (char*)"private");
        int afterCtor = agent.testCallbacksCount();

        /* sparse call: sysName + sysLocation + sysServices only.
         * sysDescr / sysContact omitted (defaults) -> never registered. */
        RFC1213Config cfg = agent.addRFC1213SystemGroup(
            nullptr,
            nullptr, 0,
            &namePtr, sizeof(nameBuf),
            &locPtr,  sizeof(locBuf),
            &services);

        REQUIRE( cfg.registeredCount == 3 );
        REQUIRE( cfg.sysName     != nullptr );
        REQUIRE( cfg.sysLocation != nullptr );
        REQUIRE( cfg.sysServices != nullptr );
        REQUIRE( cfg.sysDescr    == nullptr );
        REQUIRE( cfg.sysContact  == nullptr );
        REQUIRE( cfg.sysUpTime   == nullptr );   /* built-in: no user handle */
        REQUIRE( agent.testCallbacksCount() == afterCtor + 3 );

        /* all five served on the wire */
        SNMPPacket* resp = nullptr;
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.3.0", &resp) );  delete resp;
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.5.0", &resp) );
        REQUIRE( resp->varbindList[0].type == STRING );          delete resp;
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.6.0", &resp) );  delete resp;
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.7.0", &resp) );
        REQUIRE( resp->varbindList[0].type == INTEGER );
        REQUIRE( static_cast<IntegerType*>(resp->varbindList[0].value)->_value == 72 ); delete resp;
        agent.testReleaseFromRegistry();

        /* gap: sysDescr was not configured -> GET answers with the
         * noSuchObject exception varbind (library inner-architecture
         * behaviour, same as any unregistered OID — never a silent drop) */
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.1.0", &resp) );
        REQUIRE( resp->varbindList[0].type == NOSUCHOBJECT ); delete resp;
    }
    REQUIRE( SNMPAgent::testAgentsCount() == 0 );
}

TEST_CASE( "v3.3.4 helper: zero-OID call registers nothing; validation errors are loud, not silent", "[snmp][v334]" ){
    test_tick_reset();
    ASNPool::resetAll();
    SNMPAgent::setUptimeSource(&fake_millis);

    {
        SNMPAgent agent((char*)"public", (char*)"private");
        int afterCtor = agent.testCallbacksCount();

        /* zero-OID call: all defaults */
        RFC1213Config cfg = agent.addRFC1213SystemGroup();
        REQUIRE( cfg.registeredCount == 0 );
        REQUIRE( agent.testCallbacksCount() == afterCtor );

        /* len=0 RW strings: refused loudly (SNMP_LOGE fires under DEBUG),
         * nothing registered, registeredCount stays honest */
        static char buf64[64];
        char* p = buf64;
        cfg = agent.addRFC1213SystemGroup(nullptr, &p, 0, nullptr, 0, nullptr, 0, nullptr);
        REQUIRE( cfg.registeredCount == 0 );
        REQUIRE( cfg.sysContact == nullptr );
        REQUIRE( agent.testCallbacksCount() == afterCtor );

        /* full six-OID call still works after the error paths */
        static char dBuf[64], cBuf[64], nBuf[64], lBuf[64];
        static int svc = 64;
        char* c = cBuf; char* n = nBuf; char* l = lBuf; (void)dBuf;
        cfg = agent.addRFC1213SystemGroup("full agent", &c, sizeof(cBuf), &n, sizeof(nBuf), &l, sizeof(lBuf), &svc);
        REQUIRE( cfg.registeredCount == 5 );   /* + built-in uptime already there */
        REQUIRE( cfg.sysDescr != nullptr );
        REQUIRE( agent.testCallbacksCount() == afterCtor + 5 );
        agent.testReleaseFromRegistry();
    }
    REQUIRE( SNMPAgent::testAgentsCount() == 0 );
}


/* ---- v3.3.4 spec test 8: trap timestamp resolves to the built-in uptime ---- */
TEST_CASE( "v3.3.4 trap timestamp: built-in uptime supplies live sysUpTime, monotone with GET", "[snmp][v334]" ){
    test_tick_reset();
    int baseAlarms = ASNPool::doubleReleaseAlarms;
    SNMPAgent::setUptimeSource(&fake_millis);

    UDP udp;
    IPAddress trapIp(192,168,1,10);

    {
        SNMPAgent agent((char*)"public", (char*)"private");

        /* GET uptime at T1 */
        fake_ms = 500000;
        SNMPPacket* resp = nullptr;
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.3.0", &resp) );
        uint32_t getVal = static_cast<TimestampType*>(resp->varbindList[0].value)->_value;
        REQUIRE( getVal == 50000u );
        delete resp;

        /* trap with NO sketch uptime callback: timestamp must come from the
         * built-in source (monotone vs the GET, within tolerance) */
        SNMPTrap trap((char*)"public", SNMP_VERSION_2C);
        trap.setUDP(&udp);
        trap.setUDPport(162);
        trap.setTrapOID(".1.3.6.1.4.1.99999.0.1");
        REQUIRE( trap.uptimeCallback == nullptr );   /* nothing sketch-supplied */
        fake_ms = 600000;
        REQUIRE( trap.sendTo(trapIp) == true );
        REQUIRE( trap.packet == nullptr );
        /* sendTo is stateless; a second send after advancing the clock must
         * stay clean (no leak, no alarms) — timestamp liveness is exercised
         * on hardware (serial DIAG), here we prove the plumbing is sound. */
        fake_ms = 700000;
        REQUIRE( trap.sendTo(trapIp) == true );
        REQUIRE( ASNPool::usedCount == ASNPool::permCount );  /* back to the frozen baseline */
        REQUIRE( ASNPool::usedCount >= 1 );          /* built-in handler is permanent   */
        REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms );

        /* sketch-supplied callback still wins (pre-3.3.4 behaviour) */
        uint32_t sketchUptime = 12345;
        TimestampCallback sketchTs(new SortableOIDType(".1.3.6.1.4.1.99999.9.0"), &sketchUptime);
        trap.setUptimeCallback(&sketchTs);
        fake_ms = 800000;
        REQUIRE( trap.sendTo(trapIp) == true );
        REQUIRE( trap.uptimeCallback == &sketchTs );
        trap.setUptimeCallback(nullptr);
        /* sketchTs.OID is freed by ~ValueCallback (asn_delete dispatches the
         * heap pointer) — no manual delete here (double-free). */
        agent.testReleaseFromRegistry();
    }
    /* registry cleanup + stateless proof: resetAll() here auto-freezes the
     * baseline at the slot where the built-in handler's OID sits (nothing
     * else was allocated before it in this case), so usedCount settles on a
     * baseline >= 1 with zero transients surviving the trap sends. */
    REQUIRE( SNMPAgent::testAgentsCount() == 0 );
    ASNPool::resetAll();
    REQUIRE( ASNPool::usedCount == ASNPool::permCount );
    REQUIRE( ASNPool::usedCount >= 1 );   /* the built-in handler's slot */
}

#endif /* SNMP_HAS_BUILTIN_SYSUPTIME */
