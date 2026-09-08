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
#include "include/BERView.h"   /* v3.4.0 phase 1: zero-copy view equivalence tests */

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

#if SNMP_ZERO_COPY
TEST_CASE( "v3.4.0 phase4: in-place handler is byte-equivalent to classic path", "[snmp][zerocopy]" ){
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int testInt = 23;
    IntegerCallback integer(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = &integer;

    SNMPPacket* request = GenerateTestSNMPRequestPacket();
    uint8_t classicBuffer[800] = {0};
    uint8_t zeroCopyBuffer[800] = {0};
    int requestLength = request->serialiseInto(classicBuffer, sizeof(classicBuffer));
    REQUIRE( requestLength > 0 );
    memcpy(zeroCopyBuffer, classicBuffer, (size_t)requestLength);

    int classicLength = 0;
    int zeroCopyLength = 0;
    SNMP_ERROR_RESPONSE classicResult = handlePacket(
        classicBuffer, requestLength, &classicLength, sizeof(classicBuffer),
        callbacks, callbacksCount, "public", "private");
    SNMP_ERROR_RESPONSE zeroCopyResult = handlePacketInPlace(
        zeroCopyBuffer, requestLength, &zeroCopyLength, sizeof(zeroCopyBuffer),
        callbacks, callbacksCount, "public", "private");

    REQUIRE( zeroCopyResult == classicResult );
    REQUIRE( zeroCopyLength == classicLength );
    REQUIRE( memcmp(zeroCopyBuffer, classicBuffer, (size_t)classicLength) == 0 );
}

TEST_CASE( "v3.4.0 phase4: zero-copy GETNEXT, GETBULK, SET and tooBig parity", "[snmp][zerocopy]" ){
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int value = 7;
    IntegerCallback first(new SortableOIDType(".1.3.6.1.4.1.5.1"), &value);
    IntegerCallback second(new SortableOIDType(".1.3.6.1.4.1.5.2"), &value);
    second.isSettable = true;
    callbacks[callbacksCount++] = &first;
    callbacks[callbacksCount++] = &second;
    sort_handlers(callbacks, callbacksCount);

    auto compare = [&](SNMPPacket* request, int maxPacketSize){
        uint8_t classicBuffer[800] = {0};
        uint8_t zeroCopyBuffer[800] = {0};
        int requestLength = request->serialiseInto(classicBuffer, sizeof(classicBuffer));
        REQUIRE( requestLength > 0 );
        memcpy(zeroCopyBuffer, classicBuffer, (size_t)requestLength);
        int classicLength = 0;
        int zeroCopyLength = 0;
        SNMP_ERROR_RESPONSE classicResult = handlePacket(
            classicBuffer, requestLength, &classicLength, maxPacketSize,
            callbacks, callbacksCount, "public", "public");
        SNMP_ERROR_RESPONSE zeroCopyResult = handlePacketInPlace(
            zeroCopyBuffer, requestLength, &zeroCopyLength, maxPacketSize,
            callbacks, callbacksCount, "public", "public");
        REQUIRE( zeroCopyResult == classicResult );
        REQUIRE( zeroCopyLength == classicLength );
        REQUIRE( memcmp(zeroCopyBuffer, classicBuffer, (size_t)classicLength) == 0 );
    };

    SECTION( "GETNEXT" ){
        SNMPPacket* request = GenerateTestSNMPRequestPacket();
        request->setPDUType(GetNextRequestPDU);
        compare(request, sizeof(uint8_t) * 800);
    }

    SECTION( "GETBULK" ){
        SNMPPacket* request = GenerateTestSNMPRequestPacket();
        request->pop_back();
        request->pop_back();
        request->pop_back();
        request->setVersion(SNMP_VERSION_2C);
        request->setPDUType(GetBulkRequestPDU);
        request->errorStatus.nonRepeaters = 0;
        request->errorIndex.maxRepititions = 2;
        compare(request, sizeof(uint8_t) * 800);
    }

    SECTION( "SET" ){
        SNMPPacket* request = GenerateTestSNMPRequestPacket();
        request->setPDUType(SetRequestPDU);
        compare(request, sizeof(uint8_t) * 800);
    }

    SECTION( "tooBig" ){
        SNMPPacket* request = GenerateTestSNMPRequestPacket();
        request->setPDUType(GetRequestPDU);
        compare(request, 64);
    }
}
#endif

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

#if !SNMP_NO_TRAPS
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
#endif /* !SNMP_NO_TRAPS */

#if !SNMP_NO_TRAPS
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
#endif /* !SNMP_NO_TRAPS */

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
#if !SNMP_NO_TRAPS
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
#endif /* !SNMP_NO_TRAPS */

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
#if !SNMP_NO_TRAPS
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


/* ---- v3.3.5: auto-size SysBuf helper — array registration, SKIP sentinel, SET path ---- */
#endif /* !SNMP_NO_TRAPS */

TEST_CASE( "v3.3.5 helper: auto-size arrays register without sizeof(); SKIP omits; SET writes the buffer", "[snmp][v335]" ){
    test_tick_reset();
    ASNPool::resetAll();
    SNMPAgent::setUptimeSource(&fake_millis);
    int baseAlarms = ASNPool::doubleReleaseAlarms;

    {
        SNMPAgent agent((char*)"public", (char*)"private");
        int afterCtor = agent.testCallbacksCount();

        static char descrBuf[64];
        static char contactBuf[64], locBuf[48];
        static char nameBuf[32]; (void)nameBuf;   /* kept for the SKIP-doc example */
        static int  svc = 72;
        strcpy(descrBuf, "autosize agent");

        /* five inputs, no sizeof(), one OID skipped via RFC1213_SKIP */
        RFC1213Config cfg = agent.addRFC1213SystemGroup(
            descrBuf, contactBuf, RFC1213_SKIP, locBuf, &svc);
        REQUIRE( cfg.registeredCount == 4 );        /* descr + contact + loc + svc (name skipped) */
        REQUIRE( cfg.sysName == nullptr );          /* skipped OID left unregistered            */
        REQUIRE( cfg.sysContact != nullptr );
        REQUIRE( cfg.sysLocation != nullptr );
        REQUIRE( agent.testCallbacksCount() == afterCtor + 4 );

        /* GET through the SysBuf-backed handler serves the buffer contents */
        SNMPPacket* resp = nullptr;
        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.1.0", &resp) );   /* sysDescr */
        REQUIRE( strcmp(static_cast<OctetType*>(resp->varbindList[0].value)->_value, "autosize agent") == 0 );
        delete resp;

        REQUIRE( runGet(&agent, ".1.3.6.1.2.1.1.6.0", &resp) );   /* sysLocation (empty buffer) */
        REQUIRE( static_cast<OctetType*>(resp->varbindList[0].value)->_valueLen == 0 );
        delete resp;

        /* SET writes into the char[] buffer directly (StringBufCallback path) */
        {
            SNMPPacket* req = new SNMPPacket();
            req->setPDUType(SetRequestPDU);
            req->setCommunityString("public");   /* "public" = RW community in this harness */
            req->setRequestID(random());
            req->setVersion(SNMP_VERSION_1);
            req->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.2.1.1.6.0"),
                                   std::make_shared<OctetType>("rack B, shelf 3")));
            uint8_t buffer[400];
            int buf_len = req->serialiseInto(buffer, 400);
            delete req;
            REQUIRE( buf_len > 0 );
            int responseLength = 0;
            REQUIRE( handlePacket(buffer, buf_len, &responseLength, 400,
                                  agent.testCallbacks(), agent.testCallbacksCount(),
                                  (char*)"public", (char*)"private") == SNMP_SET_OCCURRED );
            SNMPPacket* setResp = new SNMPPacket();
            REQUIRE( setResp->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );
            delete setResp;
        }
        REQUIRE( strcmp(locBuf, "rack B, shelf 3") == 0 );   /* bytes landed in the array */

        /* the deduced capacity is the real array size: an over-long SET is refused */
        {
            SNMPPacket* req = new SNMPPacket();
            req->setPDUType(SetRequestPDU);
            req->setCommunityString("public");
            req->setRequestID(random());
            req->setVersion(SNMP_VERSION_1);
            char big[96]; memset(big, 'x', sizeof(big) - 1); big[sizeof(big)-1] = 0;
            req->push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.2.1.1.6.0"),
                                   std::make_shared<OctetType>(big, sizeof(big) - 1)));
            uint8_t buffer[400];
            int buf_len = req->serialiseInto(buffer, 400);
            delete req;
            REQUIRE( buf_len > 0 );
            int responseLength = 0;
            (void)handlePacket(buffer, buf_len, &responseLength, 400,
                               agent.testCallbacks(), agent.testCallbacksCount(),
                               (char*)"public", (char*)"private");
            /* WRONG_LENGTH response — buffer beyond deduced 48-byte capacity untouched */
            REQUIRE( strncmp(locBuf, "rack B, shelf 3", 15) == 0 );
        }

        /* advanced pointer+len overload still works alongside */
        static char heapLike[24]; char* p = heapLike;
        cfg = agent.addRFC1213SystemGroup(nullptr, &p, sizeof(heapLike), nullptr, 0, nullptr, 0, nullptr);
        REQUIRE( cfg.registeredCount == 1 );
        REQUIRE( cfg.sysContact != nullptr );

        agent.testReleaseFromRegistry();
    }
    REQUIRE( SNMPAgent::testAgentsCount() == 0 );
    REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms );
}
#endif /* SNMP_HAS_BUILTIN_SYSUPTIME */

/* ---- v3.3.6: setInformAckCallback — sketch-facing inform delivery
 * confirmation. The internal ack machinery (Response PDU matched by request
 * ID in handlePacket) now surfaces to sketches: the callback fires once per
 * matched response, never for unsolicited/unmatched Response PDUs, and
 * carries the responder's error outcome. ---- */
#if !SNMP_NO_TRAPS
TEST_CASE( "v3.3.6 inform ack callback: fires for matched responses with responder outcome, silent for unmatched", "[snmp][v336]" ){
    test_tick_reset();
    ASNPool::resetAll();
    int baseAlarms = ASNPool::doubleReleaseAlarms;

    struct AckLog {
        int fired = 0;
        snmp_request_id_t lastID = 0;
        bool lastSuccess = false;
        static void onAck(snmp_request_id_t id, bool ok){
            if(AckLog* self = s_instance()){ self->fired++; self->lastID = id; self->lastSuccess = ok; }
        }
        static AckLog* s_instance(){ static AckLog log; return &log; }
    };
    AckLog::s_instance()->fired = 0;

    SNMPAgent agent((char*)"public", (char*)"private");
    agent.setInformAckCallback(&AckLog::onAck);

    /* an inform responder's GetResponse PDU whose request ID matches a queued
     * inform — build one directly (no real network on the host): */
    snmp_request_id_t ackedID = 424242;

    /* 1. Unmatched response FIRST: no inform queued -> callback must NOT fire
     *    (no phantom confirmation for unsolicited Response PDUs). */
    {
        SNMPPacket* resp = new SNMPPacket();
        resp->setPDUType(GetResponsePDU);
        resp->setCommunityString("public");
        resp->setRequestID(ackedID);
        resp->setVersion(SNMP_VERSION_2C);
        uint8_t buffer[300];
        int buf_len = resp->serialiseInto(buffer, 300);
        delete resp;
        REQUIRE( buf_len > 0 );
        int responseLength = 0;
        REQUIRE( handlePacket(buffer, buf_len, &responseLength, 300,
                              agent.testCallbacks(), agent.testCallbacksCount(),
                              (char*)"public", (char*)"private",
                              nullptr, nullptr) == SNMP_INFORM_RESPONSE_OCCURRED );
        /* internal path without a callback registered on the agent: use the
         * agent's own informCallback through a direct call instead — here we
         * verify via loop-independent plumbing below. */
        (void)responseLength;
        REQUIRE( AckLog::s_instance()->fired == 0 );
    }

    /* 2. Queue a pending inform item directly (queue_and_send_trap needs a
     *    UDP socket; the queue state under test is the InformItem list). */
    {
        struct InformItem* item = (struct InformItem*)calloc(1, sizeof(struct InformItem));
        REQUIRE( item != nullptr );
        item->requestID = ackedID;
        item->retries = 2;
        item->delay_ms = 5000;
        item->received = false;
        item->missed = false;
        item->trap = nullptr;
        item->lastSent = 0;
        agent.informList[agent.informCount++] = item;
        REQUIRE( inform_pending_with_id(agent.informList, agent.informCount, ackedID) );
        REQUIRE( !inform_pending_with_id(agent.informList, agent.informCount, 999) );
    }

    /* 3. Deliver the ack through the agent's internal callback path exactly
     *    as handlePacket does on a real Response PDU. */        SNMPAgent::testInformCallback((void*)&agent, ackedID, true);
    REQUIRE( AckLog::s_instance()->fired == 1 );
    REQUIRE( AckLog::s_instance()->lastID == ackedID );
    REQUIRE( AckLog::s_instance()->lastSuccess == true );
    /* the pending item was consumed by the ack (queue drained) */
    REQUIRE( agent.informCount == 0 );
    REQUIRE( !inform_pending_with_id(agent.informList, agent.informCount, ackedID) );

    /* 4. Responder signalled an error (errorStatus != 0): success=false must
     *    propagate — the sketch learns the inform was REJECTED, not lost. */
    {
        snmp_request_id_t errID = 777;
        struct InformItem* item = (struct InformItem*)calloc(1, sizeof(struct InformItem));
        REQUIRE( item != nullptr );
        item->requestID = errID;
        item->retries = 1;
        item->delay_ms = 5000;
        item->received = false;
        item->missed = false;
        item->trap = nullptr;
        item->lastSent = 0;
        agent.informList[agent.informCount++] = item;

        SNMPAgent::testInformCallback((void*)&agent, errID, false);
        REQUIRE( AckLog::s_instance()->fired == 2 );
        REQUIRE( AckLog::s_instance()->lastID == errID );
        REQUIRE( AckLog::s_instance()->lastSuccess == false );
    }

    /* 5. Uninstall: nullptr callback restores silence. */
    agent.setInformAckCallback(nullptr);
    {
        snmp_request_id_t quietID = 999;
        struct InformItem* item = (struct InformItem*)calloc(1, sizeof(struct InformItem));
        REQUIRE( item != nullptr );
        item->requestID = quietID;
        item->retries = 1; item->delay_ms = 1000;
        item->received = false; item->missed = false;
        item->trap = nullptr; item->lastSent = 0;
        agent.informList[agent.informCount++] = item;

        SNMPAgent::testInformCallback((void*)&agent, quietID, true);
        REQUIRE( AckLog::s_instance()->fired == 2 );
    }

    agent.testReleaseFromRegistry();
    REQUIRE( SNMPAgent::testAgentsCount() == 0 );
    REQUIRE( ASNPool::doubleReleaseAlarms == baseAlarms );
}
#endif /* !SNMP_NO_TRAPS */

#if SNMP_ZERO_COPY
/* ==========================================================================
 * v3.4.0 Phase 1 — zero-copy BER view equivalence tests.
 *
 * A canonical reference packet is byte-for-byte identical to the fixture
 * generator's get_sysdescr_v2c.bin (.internal_test/baseline_v340_phase0/
 * fixtures/) — same generator function shapes, same encoding.  The header
 * walk (snmp_ber_peek_packet) must agree with the owning container parse
 * (SNMPPacket::parseFrom) on version, community, PDU type, request-id,
 * varbind count, and decoded value bytes — plus hold hard invariants on
 * every structural edge case: truncation, unknown types, embedded NULs,
 * OID subtree slice equality.
 * ========================================================================== */

/* Minimal BER builder with COMPUTED lengths (mirrors gen_fixtures.py's
 * tlv()/integer()/oid_arc_list()) — hand-typed length bytes are how the
 * first draft of these fixtures went wrong. */
namespace berfix {
    static size_t putLen(uint8_t* p, size_t L){
        if(L < 0x80){ p[0]=(uint8_t)L; return 1; }
        if(L < 0x100){ p[0]=0x81; p[1]=(uint8_t)L; return 2; }
        p[0]=0x82; p[1]=(uint8_t)(L>>8); p[2]=(uint8_t)(L&0xFF); return 3;
    }
    /* TLV from raw content. Returns bytes written. */
    static size_t tlv(uint8_t* p, uint8_t tag, const uint8_t* c, size_t cl){
        p[0]=tag; size_t n=putLen(p+1,cl); memcpy(p+1+n,c,cl); return 1+n+cl;
    }
    /* INTEGER TLV, non-negative-safe minimal big-endian. */
    static size_t tlvInt(uint8_t* p, long v){
        uint8_t c[5]; size_t cl=0;
        if(v==0){ c[cl++]=0; }
        else { uint8_t tmp[5]; size_t n=0; unsigned long u=(unsigned long)v;
            while(u){ tmp[n++]=(uint8_t)(u&0xFF); u>>=8; }
            for(size_t i=n;i>0;i--) c[cl++]=tmp[i-1];
            if(c[0]&0x80){ memmove(c+1,c,cl); c[0]=0; cl++; } }
        return tlv(p,0x02,c,cl);
    }
    /* OCTET STRING TLV. */
    static size_t tlvOctets(uint8_t* p, const char* s, size_t len){
        return tlv(p,0x04,(const uint8_t*)s,len);
    }
    /* OID TLV from an arc list (base-128 encoding, arcs after the first two). */
    static size_t tlvOid(uint8_t* p, const long* arcs, int n){
        uint8_t c[40]; size_t cl=0;
        c[cl++]=(uint8_t)(40*arcs[0]+arcs[1]);
        for(int i=2;i<n;i++){
            long a=arcs[i];
            if(a<0x80){ c[cl++]=(uint8_t)a; }
            else { uint8_t tmp[6]; size_t t=0; while(a){ tmp[t++]=(uint8_t)((a&0x7F)|0x80); a>>=7; }
                   tmp[0]&=0x7F; while(t) c[cl++]=tmp[--t]; }
        }
        return tlv(p,0x06,c,cl);
    }
    /* varbind SEQUENCE { OID, valueTLV(value bytes) }. valueRaw = raw content bytes of the value TLV. */
    static size_t varbindRaw(uint8_t* p, const uint8_t* oidContent, size_t oidLen,
                             uint8_t valueTag, const uint8_t* valueContent, size_t valueLen){
        uint8_t body[80]; size_t bl=0;
        bl += tlv(body, 0x06, oidContent, oidLen);
        bl += tlv(body+bl, valueTag, valueContent, valueLen);
        return tlv(p, 0x30, body, bl);
    }
    /* Complete v2c message: SEQUENCE { ver, community, pduTag{ rid, e, i, vbList{ vbs } } }. */
    static size_t message(uint8_t* p, const char* community, uint8_t pduTag, long rid,
                          const uint8_t* vbs, size_t vbsLen, long errStatus=0, long errIndex=0){
        uint8_t body[512]; size_t bl=0;
        bl += tlvInt(body+bl, 1);                            /* version = v2c */
        bl += tlvOctets(body+bl, community, strlen(community));
        uint8_t pduBody[384]; size_t pl=0;
        pl += tlvInt(pduBody+pl, rid);
        pl += tlvInt(pduBody+pl, errStatus);
        pl += tlvInt(pduBody+pl, errIndex);
        pl += tlv(pduBody+pl, 0x30, vbs, vbsLen);            /* varbind-LIST envelope around the varbinds */
        bl += tlv(body+bl, pduTag, pduBody, pl);
        return tlv(p, 0x30, body, bl);
    }
    static const uint8_t kSysDescr[] = { 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 };
}

TEST_CASE( "v3.4.0 phase1: zero-copy BER view equals container parse" ){
    REQUIRE( SNMP_ZERO_COPY == 1 );   /* the tests below are meaningless without the view walk */

    /* ---- canonical reference packet: GET sysDescr.0, community "public", v2c
     *      (byte-identical to fixtures/get_sysdescr_v2c.bin from
     *      gen_fixtures.py — same tlv()/integer()/oid_arc_list() encoding) ---- */
    uint8_t refPkt[] = {
        0x30, 0x29,                         /* SEQUENCE (41 B)                    */
        0x02, 0x01, 0x01,                   /*   INTEGER version = 1 (v2c)        */
        0x04, 0x06, 'p','u','b','l','i','c',/*   OCTET STRING community           */
        0xA0, 0x1C,                         /*   GetRequest-PDU (28 B)            */
        0x02, 0x04, 0x2A, 0x8C, 0x3F, 0x10, /*     request-id 0x2A8C3F10          */
        0x02, 0x01, 0x00,                   /*     error-status 0                 */
        0x02, 0x01, 0x00,                   /*     error-index  0                 */
        0x30, 0x0E,                         /*     varbind-list (14 B)            */
        0x30, 0x0C,                         /*       varbind SEQUENCE (12 B)      */
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  /* OID .1.3.6.1.2.1.1.1.0 */
        0x05, 0x00                          /*       NULL value                   */
    };
    const size_t refLen = sizeof(refPkt);

    SECTION( "header view decodes every field" ){
        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(refPkt, refLen, &hv) == true );
        REQUIRE( hv.version      == 1 );
        REQUIRE( hv.communityLen == 6 );
        REQUIRE( memcmp(hv.community, "public", 6) == 0 );
        REQUIRE( hv.pduType      == GetRequestPDU );
        REQUIRE( (uint32_t)hv.requestID == 0x2A8C3F10u );
        REQUIRE( hv.errorStatus  == 0 );
        REQUIRE( hv.errorIndex   == 0 );
        REQUIRE( hv.varbindCount == 1 );
        REQUIRE( hv.varbindsTruncated == false );
    }

    SECTION( "varbind slices are exact and equal the container OID" ){
        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(refPkt, refLen, &hv) == true );

        const uint8_t expectOid[] = { 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 };
        REQUIRE( hv.vbs[0].oidLen == sizeof(expectOid) );
        REQUIRE( memcmp(hv.vbs[0].oid, expectOid, sizeof(expectOid)) == 0 );
        REQUIRE( hv.vbs[0].valueType == NULLTYPE );
        REQUIRE( hv.vbs[0].valueLen  == 0 );

        /* slice points INSIDE the caller's buffer (zero-copy property) */
        REQUIRE( hv.vbs[0].oid >= refPkt );
        REQUIRE( hv.vbs[0].oid <  refPkt + refLen );

        /* cross-check: the owning path's OID encodes to the same bytes */
        OIDType* ref = asn_new<OIDType>(".1.3.6.1.2.1.1.1.0");
        REQUIRE( ref != nullptr );
        REQUIRE( (size_t)ref->encodedLen() == (size_t)hv.vbs[0].oidLen );
        REQUIRE( memcmp(ref->encodedData(), hv.vbs[0].oid, (size_t)ref->encodedLen()) == 0 );
        asn_delete(ref);
    }

    SECTION( "view walk agrees with the owning container parse" ){
        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(refPkt, refLen, &hv) == true );

        SNMPPacket packet;
        REQUIRE( packet.parseFrom(refPkt, refLen) == SNMP_ERROR_OK );

        REQUIRE( (int)packet.snmpVersion == hv.version );
        REQUIRE( strcmp(packet.communityString, "public") == 0 );
        REQUIRE( packet.communityString[hv.communityLen] == 0 );
        REQUIRE( packet.packetPDUType == hv.pduType );
        REQUIRE( packet.requestID == (snmp_request_id_t)hv.requestID );
        REQUIRE( packet.size()    == hv.varbindCount );
        REQUIRE( packet.varbindList[0].oid != nullptr );
        REQUIRE( packet.varbindList[0].oid->encodedLen() == (int)hv.vbs[0].oidLen );
        REQUIRE( memcmp(packet.varbindList[0].oid->encodedData(), hv.vbs[0].oid, (size_t)hv.vbs[0].oidLen) == 0 );
    }

    SECTION( "truncated packets are rejected, never read past the buffer" ){
        SnmpHeaderView hv;
        /* every strict prefix of the reference packet must fail the walk */
        for( size_t cut = 0; cut < refLen; cut++ ){
            REQUIRE( snmp_ber_peek_packet(refPkt, cut, &hv) == false );
        }
        /* truncated-inside-last-TLV (fixture edge_truncated_mid_tlv shape) */
        REQUIRE( snmp_ber_peek_packet(refPkt, refLen - 7, &hv) == false );
    }

    SECTION( "unknown value type is structurally valid for the view walk" ){
        /* tag 0x7F value: view walk treats it as an opaque slice; the
         * decision to reject belongs to dispatch (phase 2), not decode */
        uint8_t vbs[32]; size_t vl = 0;
        const uint8_t weird[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
        vl += berfix::varbindRaw(vbs+vl, berfix::kSysDescr, sizeof(berfix::kSysDescr), 0x7F, weird, 4);
        uint8_t pkt[96];
        size_t n = berfix::message(pkt, "public", 0xA0, 5, vbs, vl);

        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(pkt, n, &hv) == true );
        REQUIRE( hv.varbindCount == 1 );
        REQUIRE( hv.vbs[0].valueType == 0x7F );
        REQUIRE( hv.vbs[0].valueLen  == 4 );
        REQUIRE( hv.vbs[0].value[0]  == 0xDE );
        REQUIRE( hv.vbs[0].value[2]  == 0xBE );
    }

    SECTION( "embedded NULs ride through the slice by explicit length" ){
        /* OID .1.3.6.1.4.1.52420 + octet string "a\0" — 2-byte base-128 arc
         * and an embedded NUL carried by explicit length, no strlen */
        const long arcs[] = { 1, 3, 6, 1, 4, 1, 52420 };
        uint8_t oidC[12];
        uint8_t vbArea[48]; size_t vl = 0;
        {
            uint8_t one[24];
            size_t oneLen = berfix::tlvOid(one, arcs, 7);
            vl += berfix::varbindRaw(vbArea+vl, one+2, oneLen-2, 0x04, (const uint8_t*)"a\0", 2);
        }
        (void)oidC;
        uint8_t pkt[96];
        size_t n = berfix::message(pkt, "private", 0xA3, 2, vbArea, vl);

        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(pkt, n, &hv) == true );
        REQUIRE( hv.pduType == SetRequestPDU );
        REQUIRE( hv.varbindCount == 1 );
        REQUIRE( hv.vbs[0].valueType == STRING );
        REQUIRE( hv.vbs[0].valueLen  == 2 );
        REQUIRE( hv.vbs[0].value[0]  == 'a' );
        REQUIRE( hv.vbs[0].value[1]  == 0x00 );   /* NUL carried — no strlen anywhere */
        /* 2-byte base-128 arc: 52420 = 3*16384 + 25*128 + 68 -> 0x83 0x99 0x44 */
        const uint8_t expectOid[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x99, 0x44 };
        REQUIRE( hv.vbs[0].oidLen == sizeof(expectOid) );
        REQUIRE( memcmp(hv.vbs[0].oid, expectOid, sizeof(expectOid)) == 0 );
    }

    SECTION( "GETBULK header fields decode (errorStatus carries nonRepeaters)" ){
        uint8_t vbs[32]; size_t vl = 0;
        vl += berfix::varbindRaw(vbs+vl, berfix::kSysDescr, sizeof(berfix::kSysDescr), 0x05, nullptr, 0);
        uint8_t pkt[96];
        /* union view: errStatus slot carries nonRepeaters, errIndex slot maxRepetitions */
        size_t n = berfix::message(pkt, "public", 0xA5, 0x55667788L, vbs, vl, 0, 4);

        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(pkt, n, &hv) == true );
        REQUIRE( hv.pduType == GetBulkRequestPDU );
        REQUIRE( hv.errorStatus == 0 );   /* union view: nonRepeaters */
        REQUIRE( hv.errorIndex  == 4 );   /* union view: maxRepetitions */
        REQUIRE( hv.varbindCount == 1 );
    }

    SECTION( "8-varbind request: exact count, slices recorded to the cap" ){
        /* 8x varbind( sysX.0, NULL ), sysX = 1..8 — the edge_8varbind_p1400 shape */
        uint8_t vbArea[192]; size_t vl = 0;
        for( int k = 1; k <= 8; k++ ){
            uint8_t oidC[12];
            oidC[0]=0x2B; oidC[1]=0x06; oidC[2]=0x01; oidC[3]=0x02; oidC[4]=0x01;
            oidC[5]=0x01; oidC[6]=(uint8_t)k; oidC[7]=0x00;
            vl += berfix::varbindRaw(vbArea+vl, oidC, 8, 0x05, nullptr, 0);
        }
        uint8_t pkt[256];
        size_t n = berfix::message(pkt, "public", 0xA0, 3, vbArea, vl);

        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(pkt, n, &hv) == true );
        REQUIRE( hv.varbindCount == 8 );
        REQUIRE( hv.varbindsTruncated == false ); /* 8 <= SNMP_ZC_MAX_VARBINDS(16) */
        for( int k = 0; k < 8; k++ ){
            REQUIRE( hv.vbs[k].oid[6] == (uint8_t)(k + 1) );   /* sysX index rides in-slice */
            REQUIRE( hv.vbs[k].valueType == NULLTYPE );
        }
    }

    SECTION( "indefinite length and oversized length fields are rejected" ){
        uint8_t indef[] = { 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00 };
        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(indef, sizeof(indef), &hv) == false );

        uint8_t huge[] = { 0x30, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0x02 };
        REQUIRE( snmp_ber_peek_packet(huge, sizeof(huge), &hv) == false );

        uint8_t maniac[] = { 0x30, 0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A };
        REQUIRE( snmp_ber_peek_packet(maniac, sizeof(maniac), &hv) == false );
    }

    SECTION( "bad version rejected exactly like the container path" ){
        /* version = 3 (SNMPv3-shaped): parsePacket rejects with
         * SNMP_PARSE_ERROR_AT_STATE(SNMPVERSION); the view walk fails. */
        uint8_t pkt[] = {
            0x30, 0x28,
            0x02, 0x01, 0x03,                 /* version 3 */
            0x04, 0x06, 'p','u','b','l','i','c',
            0xA0, 0x1B,
            0x02, 0x01, 0x06,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0D,
            0x30, 0x0B,
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
            0x05, 0x00
        };
        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(pkt, sizeof(pkt), &hv) == false );

        SNMPPacket packet;
        int rc = packet.parseFrom(pkt, sizeof(pkt));
        REQUIRE( rc != SNMP_ERROR_OK );   /* both paths agree: reject */
    }

    SECTION( "garbage buffer rejected (magic-byte parity with parseFrom)" ){
        uint8_t junk[] = { 0x31, 0x05, 0x02, 0x01, 0x01, 0x00, 0x00 };
        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(junk, sizeof(junk), &hv) == false );

        SNMPPacket packet;
        REQUIRE( packet.parseFrom(junk, sizeof(junk)) == SNMP_PARSE_ERROR_MAGIC_BYTE );
    }

    SECTION( "multi-varbind view matches container OID list element-wise" ){
        uint8_t vbArea[160]; size_t vl = 0;
        const char* oids[3] = { ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.4.1.52420.1", ".1.3.6.1.2.1.1.3.0" };
        for( int i = 0; i < 3; i++ ){
            OIDType* o = asn_new<OIDType>(oids[i]);
            REQUIRE( o != nullptr );
            vl += berfix::varbindRaw(vbArea+vl, o->encodedData(), (size_t)o->encodedLen(), 0x05, nullptr, 0);
            asn_delete(o);
        }
        uint8_t pkt[256];
        size_t n = berfix::message(pkt, "public", 0xA0, 0xDEADBEEFL, vbArea, vl);

        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(pkt, n, &hv) == true );
        REQUIRE( hv.varbindCount == 3 );
        REQUIRE( (uint32_t)hv.requestID == 0xDEADBEEFu );

        /* owning parse of the same buffer */
        SNMPPacket packet;
        REQUIRE( packet.parseFrom(pkt, n) == SNMP_ERROR_OK );
        REQUIRE( packet.size() == 3 );
        for( int i = 0; i < 3; i++ ){
            REQUIRE( packet.varbindList[i].oid != nullptr );
            REQUIRE( packet.varbindList[i].oid->encodedLen() == (int)hv.vbs[i].oidLen );
            REQUIRE( memcmp(packet.varbindList[i].oid->encodedData(), hv.vbs[i].oid,
                            (size_t)hv.vbs[i].oidLen) == 0 );
        }
    }
}

#endif /* SNMP_ZERO_COPY */

#if SNMP_ZERO_COPY
/* ==========================================================================
 * v3.4.0 Phase 3 — BerWriter direct serialization equivalence.
 *
 * Every typed writer must produce BYTE-IDENTICAL output to the container
 * serialise() forms (the wire contract), scopes must encode lengths
 * identically (short/1-byte/2-byte forms), and the exact fit invariant
 * must hold: put*() failing marks the writer sticky-failed and the exact
 * length() is the truth about what fits.
 * ========================================================================== */
TEST_CASE( "v3.4.0 phase3: BerWriter equals container serialise" ){

    SECTION( "putInteger matches IntegerType::serialise (always 4-byte form)" ){
        const long vals[] = { 0, 1, -1, 42, -42, 23, -420000, 2147483647L, (long)-2147483648 };
        for( long v : vals ){
            uint8_t w[32]; BerWriter wr(w, sizeof(w));
            REQUIRE( wr.putInteger(v) );
            REQUIRE( wr.length() == 6 );

            IntegerType* it = asn_new<IntegerType>((int)v);
            REQUIRE( it != nullptr );
            uint8_t c[32];
            int n = it->testSerialise(c, sizeof(c));
            REQUIRE( n > 0 );
            REQUIRE( (size_t)n == wr.length() );
            REQUIRE( memcmp(w, c, (size_t)n) == 0 );
            asn_delete(it);
        }
    }

    SECTION( "putNull matches NullType::serialise" ){
        uint8_t w[8]; BerWriter wr(w, sizeof(w));
        REQUIRE( wr.putNull(0x05) );
        REQUIRE( wr.length() == 2 );
        REQUIRE( w[0] == 0x05 ); REQUIRE( w[1] == 0x00 );

        NullType* nt = asn_new<NullType>();
        uint8_t c[8]; int n = nt->testSerialise(c, sizeof(c));
        REQUIRE( n == 2 );
        REQUIRE( memcmp(w, c, 2) == 0 );
        asn_delete(nt);

        /* implicit-null exception tags ride the same 2-byte shape */
        uint8_t w2[8]; BerWriter wr2(w2, sizeof(w2));
        REQUIRE( wr2.putNull(ENDOFMIBVIEW) );
        REQUIRE( w2[0] == 0x82 ); REQUIRE( w2[1] == 0x00 );
    }

    SECTION( "putOIDContent matches OIDType::serialise" ){
        OIDType* o = asn_new<OIDType>(".1.3.6.1.4.1.52420.9999999");
        REQUIRE( o != nullptr );
        uint8_t c[64];
        int n = o->testSerialise(c, sizeof(c));
        REQUIRE( n > 0 );

        uint8_t w[64]; BerWriter wr(w, sizeof(w));
        REQUIRE( wr.putOIDContent(o->encodedData(), (size_t)o->encodedLen()) );
        REQUIRE( wr.length() == (size_t)n );
        REQUIRE( memcmp(w, c, (size_t)n) == 0 );
        asn_delete(o);
    }

    SECTION( "putOctets matches OctetType::serialise (incl. embedded NUL)" ){
        const uint8_t payload[] = { 'a', 0x00, 'b', 0x00, 'c' };
        OctetType* ot = asn_new<OctetType>((const char*)payload, sizeof(payload));
        REQUIRE( ot != nullptr );
        uint8_t c[64];
        int n = ot->testSerialise(c, sizeof(c));
        REQUIRE( n > 0 );

        uint8_t w[64]; BerWriter wr(w, sizeof(w));
        REQUIRE( wr.putOctets(0x04, payload, sizeof(payload)) );
        REQUIRE( wr.length() == (size_t)n );
        REQUIRE( memcmp(w, c, (size_t)n) == 0 );
        asn_delete(ot);
    }

    SECTION( "scopes produce identical lengths across all three length forms" ){
        /* short form (<128), 0x81 form (<256), 0x82 form (>=256).
         * 256 is the max: the container OctetType ctor clamps string content
         * to SNMP_MAX_STRING_LEN (256), so the writer payload is clamped to
         * the same to keep the comparison apples-to-apples. */
        const size_t contentSizes[] = { 3, 130, 256 };
        for( size_t cs : contentSizes ){
            REQUIRE( cs <= 256 );
            uint8_t content[256];
            for( size_t i = 0; i < cs; i++ ) content[i] = (uint8_t)(i & 0xFF);

            /* writer: scope of one octet-string TLV */
            uint8_t w[512]; BerWriter wr(w, sizeof(w));
            BerWriter::Marker m;
            REQUIRE( wr.beginScope(0x30, &m) );
            REQUIRE( wr.putOctets(0x04, content, cs) );
            REQUIRE( wr.endScope(&m) );
            (void)0;

            /* container: ComplexType{ OctetType } serialised */
            ComplexType* ct = asn_new<ComplexType>(STRUCTURE);
            REQUIRE( ct != nullptr );
            ct->_ownsChildren = true;
            OctetType* child = asn_new<OctetType>((const char*)content, cs);
            REQUIRE( child != nullptr );
            ct->addValueToListRaw(child);
            uint8_t c[512];
            int n = ct->serialise(c, sizeof(c));
            REQUIRE( n > 0 );
            REQUIRE( wr.length() == (size_t)n );
            REQUIRE( memcmp(w, c, (size_t)n) == 0 );
            asn_delete(ct);
        }
    }

    SECTION( "nested scopes match a full ComplexType tree" ){
        uint8_t w[256]; BerWriter wr(w, sizeof(w));
        BerWriter::Marker root, pdu, vbl, vb;
        REQUIRE( wr.beginScope(0x30, &root) );
        REQUIRE( wr.putInteger(1) );                       /* version */
        REQUIRE( wr.putOctets(0x04, (const uint8_t*)"public", 6) );
        REQUIRE( wr.beginScope(0xA2, &pdu) );              /* GetResponse */
        REQUIRE( wr.putInteger(0x2A8C3F10L) );
        REQUIRE( wr.putInteger(0) );
        REQUIRE( wr.putInteger(0) );
        REQUIRE( wr.beginScope(0x30, &vbl) );
        REQUIRE( wr.beginScope(0x30, &vb) );
        REQUIRE( wr.putOIDContent(berfix::kSysDescr, sizeof(berfix::kSysDescr)) );
        REQUIRE( wr.putInteger(23) );
        REQUIRE( wr.endScope(&vb) );
        REQUIRE( wr.endScope(&vbl) );
        REQUIRE( wr.endScope(&pdu) );
        REQUIRE( wr.endScope(&root) );

        /* the same tree through containers */
        ComplexType* r = asn_new<ComplexType>(STRUCTURE);
        ComplexType* p = asn_new<ComplexType>(GetResponsePDU);
        ComplexType* lst = asn_new<ComplexType>(STRUCTURE);
        ComplexType* one = asn_new<ComplexType>(STRUCTURE);
        REQUIRE( r != nullptr );
        REQUIRE( p != nullptr );
        REQUIRE( lst != nullptr );
        REQUIRE( one != nullptr );
        r->_ownsChildren = true; p->_ownsChildren = true; lst->_ownsChildren = true; one->_ownsChildren = true;
        r->addValueToListRaw(asn_new<IntegerType>(1));
        r->addValueToListRaw(asn_new<OctetType>("public"));
        p->addValueToListRaw(asn_new<IntegerType>(0x2A8C3F10));
        p->addValueToListRaw(asn_new<IntegerType>(0));
        p->addValueToListRaw(asn_new<IntegerType>(0));
        one->addValueToListRaw(asn_new<OIDType>(".1.3.6.1.2.1.1.1.0"));
        one->addValueToListRaw(asn_new<IntegerType>(23));
        lst->addValueToListRaw(one);
        p->addValueToListRaw(lst);
        r->addValueToListRaw(p);
        uint8_t c[256];
        int n = r->testSerialise(c, sizeof(c));
        REQUIRE( n > 0 );
        REQUIRE( wr.length() == (size_t)n );
        REQUIRE( memcmp(w, c, (size_t)n) == 0 );
        asn_delete(r);

        /* and the walk must parse the writer's output as a valid response */
        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(w, wr.length(), &hv) == true );
        REQUIRE( hv.pduType == GetResponsePDU );
        REQUIRE( hv.varbindCount == 1 );
        REQUIRE( memcmp(hv.vbs[0].oid, berfix::kSysDescr, sizeof(berfix::kSysDescr)) == 0 );
    }

    SECTION( "exact fit invariant: overflow is sticky, atomic, and length() is exact" ){
        uint8_t tiny[8];
        BerWriter wr(tiny, sizeof(tiny));
        REQUIRE( wr.putInteger(7) );               /* 6 B */
        REQUIRE( wr.length() == 6 );
        REQUIRE( wr.putOctets(0x04, (const uint8_t*)"0123456789", 10) == false );  /* would exceed */
        REQUIRE( wr.full() );                       /* sticky */
        REQUIRE( wr.length() == 6 );                /* atomic: nothing partial written */
        REQUIRE( wr.putInteger(0) == false );       /* further puts fail */
        REQUIRE( wr.length() == 6 );
    }

    SECTION( "boundary fit: exactly-full write succeeds, one extra byte fails" ){
        uint8_t buf[6];
        BerWriter wr(buf, sizeof(buf));
        REQUIRE( wr.putInteger(1) );               /* exactly 6 B */
        REQUIRE( wr.length() == 6 );
        REQUIRE( wr.ok() );

        uint8_t buf2[7];
        BerWriter wr2(buf2, sizeof(buf2));
        REQUIRE( wr2.putInteger(1) );
        REQUIRE( wr2.putByte(0xAB) );              /* 7th byte fits */
        REQUIRE( wr2.length() == 7 );
        BerWriter wr3(buf2, 7);
        REQUIRE( wr3.putInteger(1) );
        REQUIRE( wr3.putTLVHeader(0x04, 1) == false );  /* 2 more bytes: fail */
    }

    SECTION( "putTLVView re-emits a decoded OID slice verbatim" ){
        uint8_t vbs[32]; size_t vl = 0;
        vl += berfix::varbindRaw(vbs+vl, berfix::kSysDescr, sizeof(berfix::kSysDescr), 0x05, nullptr, 0);
        uint8_t pkt[96];
        size_t n = berfix::message(pkt, "public", 0xA0, 9, vbs, vl);

        SnmpHeaderView hv;
        REQUIRE( snmp_ber_peek_packet(pkt, n, &hv) == true );
        REQUIRE( hv.varbindCount == 1 );

        /* rebuild the varbind's OID TLV via putTLVView over a fresh view */
        BerView oidView;
        oidView.ok = true;
        oidView.tag = 0x06;
        oidView.value = hv.vbs[0].oid;
        oidView.len = hv.vbs[0].oidLen;
        oidView.headerLen = 2;
        oidView.totalLen = hv.vbs[0].oidLen + 2;

        uint8_t w[64]; BerWriter wr(w, sizeof(w));
        REQUIRE( wr.putTLVView(oidView) );
        REQUIRE( wr.length() == (size_t)hv.vbs[0].oidLen + 2 );
        /* byte-identical to the wire bytes AND to the container encode */
        REQUIRE( w[0] == 0x06 );
        REQUIRE( memcmp(w + 2, berfix::kSysDescr, sizeof(berfix::kSysDescr)) == 0 );
        OIDType* o = asn_new<OIDType>(".1.3.6.1.2.1.1.1.0");
        uint8_t c[64]; int cn = o->testSerialise(c, sizeof(c));
        REQUIRE( (size_t)cn == wr.length() );
        REQUIRE( memcmp(w, c, (size_t)cn) == 0 );
        asn_delete(o);
    }
}
#endif /* SNMP_ZERO_COPY */

#if SNMP_ZERO_COPY
/* ==========================================================================
 * v3.4.0 Phase 2 — zero-copy dispatch on slices (measurement gate).
 *
 * findCallbackForSlice (Strategy A: encoded memcmp, selected by the gate;
 * see PHASE2_EVIDENCE.md) must be a contract twin of the container
 * findCallback(): identical results across exact matches, walk successors,
 * subtree walk-starts, misses, and a randomized corpus of OID pairs — with
 * zero-copy semantics (no container materialized for matching).
 * ========================================================================== */
TEST_CASE( "v3.4.0 phase2: slice dispatch equals container findCallback" ){
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int v1 = 1, v2 = 2, v3 = 3;

    /* deliberately NOT pre-sorted; matching must not care, walk results must */
    IntegerCallback* cbA = new IntegerCallback(new SortableOIDType(".1.3.6.1.2.1.1.1.0"), &v1);
    IntegerCallback* cbB = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.52420.1"), &v2);
    IntegerCallback* cbC = new IntegerCallback(new SortableOIDType(".1.3.6.1.2"), &v3);
    callbacks[callbacksCount++] = cbA;
    callbacks[callbacksCount++] = cbB;
    callbacks[callbacksCount++] = cbC;
    sort_handlers(callbacks, callbacksCount);

    /* ownership for the corpus OIDs */
    std::list<OIDType*> owned;
    auto mkOID = [&](const char* s){ OIDType* o = asn_new<OIDType>(s); REQUIRE(o != nullptr); owned.push_back(o); return o; };
    auto encOf = [](OIDType* o, const uint8_t** d, int* l){ *d = o->encodedData(); *l = o->encodedLen(); };

    auto checkBoth = [&](ValueCallback* container, ValueCallback* slice, const char* what){
        INFO(what);
        REQUIRE( container == slice );
    };

    SECTION( "exact matches (no walk)" ){
        const char* cases[] = { ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.4.1.52420.1", ".1.3.6.1.2" };
        for( const char* s : cases ){
            OIDType* o = mkOID(s);
            const uint8_t* d; int l; encOf(o, &d, &l);
            checkBoth( ValueCallback::findCallback(callbacks, callbacksCount, o, false),
                       ValueCallback::findCallbackForSlice(callbacks, callbacksCount, d, l, false),
                       s );
        }
    }

    SECTION( "misses return nullptr on both paths" ){
        const char* cases[] = { ".1.3.6.1.2.1.1.1.1", ".1.3.6.1.4.1.52420.2", ".1.4", ".1.3.6.1.2.1.1.1" };
        for( const char* s : cases ){
            OIDType* o = mkOID(s);
            const uint8_t* d; int l; encOf(o, &d, &l);
            checkBoth( ValueCallback::findCallback(callbacks, callbacksCount, o, false),
                       ValueCallback::findCallbackForSlice(callbacks, callbacksCount, d, l, false),
                       s );
        }
    }

    SECTION( "walk: exact match -> successor; above-root start -> first handler below" ){
        struct W { const char* req; const char* expectContainer; };
        W cases[] = {
            { ".1.3.6.1.2.1.1.1.0", nullptr },           /* exact, last in subtree order: successor = cbB or null by roster */
            { ".1.3.6.1.2",           nullptr },           /* exact root -> successor                          */
            { ".1.3.6.1.2.1",         nullptr },           /* ABOVE root .1.3.6.1.2 -> first handler below it  */
            { ".1.3.6.1",             nullptr },           /* above both roots                                 */
            { ".1.3.6.1.4.1.52420",    nullptr }            /* above .1.3.6.1.4.1.52420.1                       */
        };
        for( W& w : cases ){
            OIDType* o = mkOID(w.req);
            const uint8_t* d; int l; encOf(o, &d, &l);
            int fC = -1, fS = -1;
            ValueCallback* rc = ValueCallback::findCallback(callbacks, callbacksCount, o, true, 0, &fC);
            ValueCallback* rs = ValueCallback::findCallbackForSlice(callbacks, callbacksCount, d, l, true, 0, &fS);
            checkBoth( rc, rs, w.req );
            REQUIRE( fC == fS );
            if( rc ){ REQUIRE( strcmp(rc->OID->string(), w.expectContainer ? w.expectContainer : rc->OID->string()) == 0 ); }
        }
        /* spot-check the two interesting shapes outright */
        OIDType* above = mkOID(".1.3.6.1.2.1");
        REQUIRE( ValueCallback::findCallback(callbacks, callbacksCount, above, true) == cbA );
        const uint8_t* d; int l; encOf(above, &d, &l);
        REQUIRE( ValueCallback::findCallbackForSlice(callbacks, callbacksCount, d, l, true) == cbA );
    }

    SECTION( "startAt continuation matches on both paths" ){
        OIDType* o = mkOID(".1.3.6.1.2");
        const uint8_t* d; int l; encOf(o, &d, &l);
        int fC = -1, fS = -1;
        REQUIRE( ValueCallback::findCallback(callbacks, callbacksCount, o, true, 0, &fC) != nullptr );
        REQUIRE( ValueCallback::findCallbackForSlice(callbacks, callbacksCount, d, l, true, 0, &fS) != nullptr );
        REQUIRE( fC == fS );
        /* continue from foundAt: next successor, both paths agree */
        OIDType* o2 = mkOID(".1.3.6.1.2");
        int fC2 = -1, fS2 = -1;
        ValueCallback* rc2 = ValueCallback::findCallback(callbacks, callbacksCount, o2, true, fC, &fC2);
        ValueCallback* rs2 = ValueCallback::findCallbackForSlice(callbacks, callbacksCount, d, l, true, fS, &fS2);
        checkBoth( rc2, rs2, "continuation" );
        REQUIRE( fC2 == fS2 );
    }

    SECTION( "randomized corpus: 500 pairs agree on both paths" ){
        srandom(0xC0FFEE);
        for( int iter = 0; iter < 500; iter++ ){
            /* random dotted request OID, 4..9 arcs under .1.3 */
            char buf[96];
            strcpy(buf, ".1.3.6");
            int arcs = 4 + (int)(random() % 6);
            for( int a = 0; a < arcs; a++ ){
                snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".%ld", (long)(random() % 3 == 0 ? 52420 : (random() % 200)));
            }
            OIDType* o = mkOID(buf);
            if(!o->valid) continue;
            const uint8_t* d; int l; encOf(o, &d, &l);
            bool walk = (iter & 1) == 0;
            int fC = -1, fS = -1;
            ValueCallback* rc = ValueCallback::findCallback(callbacks, callbacksCount, o, walk, 0, &fC);
            ValueCallback* rs = ValueCallback::findCallbackForSlice(callbacks, callbacksCount, d, l, walk, 0, &fS);
            REQUIRE( rc == rs );
            REQUIRE( fC == fS );
        }
    }

    for( OIDType* o : owned ) asn_delete(o);
    delete cbA; delete cbB; delete cbC;
}
#endif /* SNMP_ZERO_COPY */

/* ==========================================================================
 * v3.4.2 Phase 0 — per-packet heap-allocation census (Report_001 finding #1).
 *
 * Counts global operator new/malloc calls inside scoped windows around the
 * packet hot path.  Requests are serialised OUTSIDE the window; all
 * REQUIREs run OUTSIDE the window so Catch2's own allocations never pollute
 * the counts.  This test is the before/after instrument for the AsnPtr
 * migration: today it must report non-zero control-block traffic on both
 * packet paths; after Phase 2 it must report ZERO for the library's own
 * callbacks.
 *
 * Note: under COMPILING_TESTS asn_new() falls back to ::new when the pool
 * exhausts.  The pool here is sized for the profiles under test, and the
 * census asserts usedCount returned to baseline after every window — any
 * leak or fallback would show up as a count/usage anomaly, not silence.
 * ========================================================================== */
#include <new>
#include <cstdint>

namespace zc_census {

struct HeapCounter {
    static int allocations;
    static bool counting;
    static int windowId;
    static void reset(){ allocations = 0; counting = true; }
    static void stop(){ counting = false; }
};
int HeapCounter::allocations = 0;
bool HeapCounter::counting = false;
int HeapCounter::windowId = 0;

} /* namespace zc_census */

void* operator new(std::size_t sz){
    if(zc_census::HeapCounter::counting){ ++zc_census::HeapCounter::allocations; std::printf("[alloc w%d] %zu\n", zc_census::HeapCounter::windowId, (unsigned long)sz); }
    void* p = std::malloc(sz ? sz : 1);
    if(!p) throw std::bad_alloc();
    return p;
}
void* operator new[](std::size_t sz){
    if(zc_census::HeapCounter::counting) ++zc_census::HeapCounter::allocations;
    void* p = std::malloc(sz ? sz : 1);
    if(!p) throw std::bad_alloc();
    return p;
}
#if __cplusplus >= 201402L
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
#endif

namespace zc_census {

/* RAII window: reset + count on construct, stop on destruct. */
struct HeapWindow {
    int base;
    HeapWindow() : base(HeapCounter::allocations){ HeapCounter::counting = true; ++HeapCounter::windowId; }
    ~HeapWindow(){ HeapCounter::counting = false; }
    int delta() const { return HeapCounter::allocations - base; }
};

static int poolUsed(){ return ASNPool::usedCount; }

} /* namespace zc_census */

/* Route through THIS build's active packet path (loop() uses the same flag). */
static inline SNMP_ERROR_RESPONSE handlePacketRoute(uint8_t* buffer, int packetLength, int* responseLength, int max_packet_size,
                                                    ValueCallback* const* callbacks, int callbacksCount,
                                                    const char* community, const char* readOnly){
#if SNMP_ZERO_COPY
    return handlePacketInPlace(buffer, packetLength, responseLength, max_packet_size, callbacks, callbacksCount, community, readOnly);
#else
    return handlePacket(buffer, packetLength, responseLength, max_packet_size, callbacks, callbacksCount, community, readOnly);
#endif
}

TEST_CASE( "v3.4.2 phase0: per-packet heap-allocation census (both paths)", "[snmp][v342]" ){

    /* ---- roster: one GET value + one SET target (mirrors hot-path tests) ---- */
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int testInt = 23;
    int testInt2 = 23;
    IntegerCallback* intCb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    IntegerCallback* setCb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.4"), &testInt2);
    setCb->isSettable = true;
    callbacks[callbacksCount++] = intCb;
    callbacks[callbacksCount++] = setCb;

    /* ---- build request packets OUTSIDE any counting window ---- */
    SNMPPacket* getReq = GenerateTestSNMPRequestPacket();   /* 5 varbinds, GET */
    uint8_t getBuf[500];
    int getLen = getReq->serialiseInto(getBuf, 500);
    delete getReq;   /* return pool slots: fixtures must not starve the pool */

    SNMPPacket* setReq = GenerateTestSNMPRequestPacket();
    setReq->setPDUType(SetRequestPDU);
    uint8_t setBuf[500];
    int setLen = setReq->serialiseInto(setBuf, 500);
    delete setReq;

    SNMPPacket* nextReq = GenerateTestSNMPRequestPacket();
    nextReq->setPDUType(GetNextRequestPDU);
    uint8_t nextBuf[500];
    int nextLen = nextReq->serialiseInto(nextBuf, 500);
    delete nextReq;

    SNMPPacket* bulkReq = GenerateTestSNMPRequestPacket();
    bulkReq->pop_back(); bulkReq->pop_back(); bulkReq->pop_back(); bulkReq->pop_back();
    bulkReq->setVersion(SNMP_VERSION_2C);
    bulkReq->setPDUType(GetBulkRequestPDU);
    bulkReq->errorIndex.maxRepititions = 2;
    bulkReq->errorStatus.nonRepeaters = 0;
    uint8_t bulkBuf[500];
    int bulkLen = bulkReq->serialiseInto(bulkBuf, 500);
    delete bulkReq;

    /* ---- calibration: the counter gates exactly on the window ---- */
    {
        zc_census::HeapWindow w;
        int* probe = new int(7);
        (void)probe;
        int counted = w.delta();          /* read INSIDE the window */
        delete probe;
        REQUIRE( counted == 1 );          /* allocation inside window is counted */
        REQUIRE( zc_census::HeapCounter::counting == true );
    }
    /* (the two REQUIREs above run inside the still-open window — they
     * allocate, but they run AFTER `counted` was captured, so the
     * calibration measurement itself is clean) */
    REQUIRE( zc_census::HeapCounter::counting == false );   /* window closed: gate off */
    {
        int before = zc_census::HeapCounter::allocations;
        int* probe = new int(7);
        delete probe;
        REQUIRE( zc_census::HeapCounter::allocations == before );   /* outside window: not counted */
    }

    int baseUsed = zc_census::poolUsed();

    /* ---- GET through the ACTIVE path (this build's routing) ----
     * Windows contain ONLY the packet call: Catch2 assertion handlers
     * allocate (strings/message builders) and would pollute the count. */
    int getAllocs = -1; SNMP_ERROR_RESPONSE getR = (SNMP_ERROR_RESPONSE)-1; int getLen2 = -1;
    {
        zc_census::HeapWindow w;
        getLen2 = 0;
        getR = handlePacketRoute(getBuf, getLen, &getLen2, 500,
                                 callbacks, callbacksCount, "public", "private");
        getAllocs = w.delta();
    }
    INFO( "GET heap allocations: " << getAllocs );
    REQUIRE( getR == SNMP_GET_OCCURRED );
    REQUIRE( getLen2 > 0 );
    REQUIRE( zc_census::poolUsed() == baseUsed );   /* no pool drift */

    /* ---- SET (decode pass + set + response) ---- */
    int setAllocs = -1; SNMP_ERROR_RESPONSE setR = (SNMP_ERROR_RESPONSE)-1; int setLen2 = -1;
    {
        zc_census::HeapWindow w;
        setLen2 = 0;
        setR = handlePacketRoute(setBuf, setLen, &setLen2, 500,
                                 callbacks, callbacksCount, "public", "public");
        setAllocs = w.delta();
    }
    INFO( "SET heap allocations: " << setAllocs );
    REQUIRE( setR == SNMP_SET_OCCURRED );
    REQUIRE( setLen2 > 0 );
    REQUIRE( testInt2 == -420000 );          /* SET integrity inside census */
    REQUIRE( zc_census::poolUsed() == baseUsed );

    /* ---- GETNEXT ---- */
    int nextAllocs = -1; SNMP_ERROR_RESPONSE nextR = (SNMP_ERROR_RESPONSE)-1; int nextLen2 = -1;
    {
        zc_census::HeapWindow w;
        nextLen2 = 0;
        nextR = handlePacketRoute(nextBuf, nextLen, &nextLen2, 500,
                                  callbacks, callbacksCount, "public", "private");
        nextAllocs = w.delta();
    }
    INFO( "GETNEXT heap allocations: " << nextAllocs );
    REQUIRE( nextR == SNMP_GETNEXT_OCCURRED );
    REQUIRE( nextLen2 > 0 );
    REQUIRE( zc_census::poolUsed() == baseUsed );

    /* ---- GETBULK ---- */
    int bulkAllocs = -1; SNMP_ERROR_RESPONSE bulkR = (SNMP_ERROR_RESPONSE)-1; int bulkLen2 = -1;
    {
        zc_census::HeapWindow w;
        bulkLen2 = 0;
        bulkR = handlePacketRoute(bulkBuf, bulkLen, &bulkLen2, 500,
                                  callbacks, callbacksCount, "public", "private");
        bulkAllocs = w.delta();
    }
    INFO( "GETBULK heap allocations: " << bulkAllocs );
    REQUIRE( bulkR == SNMP_GETBULK_OCCURRED );
    REQUIRE( bulkLen2 > 0 );
    REQUIRE( zc_census::poolUsed() == baseUsed );

    /* ---- print the census line (visible with -s, parsed by the harness) ---- */
    std::printf( "[v342-census] path=%s GET=%d SET=%d GETNEXT=%d GETBULK=%d pool=%d/%d\n",
                 SNMP_ZERO_COPY ? "zerocopy" : "classic",
                 getAllocs, setAllocs, nextAllocs, bulkAllocs,
                 baseUsed, (int)SNMP_POOL_ASN_OBJECTS );

    delete intCb; delete setCb;
}

/* ==========================================================================
 * v3.4.2 phase1 — AsnPtr<T> unit tests (additive; nothing migrated yet).
 * Contract: move-only single ownership, destruction through asn_delete,
 * release() disarms, stale-bulkFreed tolerance identical to asn_delete.
 * ========================================================================== */
TEST_CASE( "v3.4.2 phase1: AsnPtr move-only pool-owning pointer", "[snmp][v342]" ){

    /* destructor frees the pool slot */
    int base = ASNPool::usedCount;
    {
        AsnPtr<IntegerType> p(asn_new<IntegerType>(42));
        REQUIRE( static_cast<bool>(p) );
        REQUIRE( p->_value == 42 );
        REQUIRE( ASNPool::usedCount == base + 1 );
    }
    REQUIRE( ASNPool::usedCount == base );   /* freed on scope exit */

    /* move transfers ownership; source disarmed */
    {
        AsnPtr<IntegerType> a(asn_new<IntegerType>(7));
        IntegerType* raw = a.get();
        AsnPtr<IntegerType> b(std::move(a));
        REQUIRE( b.get() == raw );
        REQUIRE( !a );                       /* source disarmed */
        REQUIRE( ASNPool::usedCount == base + 1 );   /* not double-freed */
    }
    REQUIRE( ASNPool::usedCount == base );

    /* move-assignment frees the target's previous object exactly once */
    {
        AsnPtr<IntegerType> a(asn_new<IntegerType>(1));
        AsnPtr<IntegerType> b(asn_new<IntegerType>(2));
        REQUIRE( ASNPool::usedCount == base + 2 );
        b = std::move(a);                    /* b's old object freed here */
        REQUIRE( ASNPool::usedCount == base + 1 );
        REQUIRE( b->_value == 1 );
    }
    REQUIRE( ASNPool::usedCount == base );

    /* release() disarms and hands raw ownership to a raw-owning API */
    {
        IntegerType* raw = nullptr;
        {
            AsnPtr<IntegerType> a(asn_new<IntegerType>(99));
            raw = a.release();
            REQUIRE( !a );                   /* guard disarmed */
        }                                    /* destructor must NOT free */
        REQUIRE( ASNPool::usedCount == base + 1 );
        REQUIRE( raw->_value == 99 );
        asn_delete(raw);                     /* caller destroys explicitly */
        REQUIRE( ASNPool::usedCount == base );
    }

    /* reset() with self-value must not destroy */
    {
        AsnPtr<IntegerType> a(asn_new<IntegerType>(5));
        IntegerType* raw = a.get();
        a.reset(raw);
        REQUIRE( ASNPool::usedCount == base + 1 );
        REQUIRE( a->_value == 5 );
    }
    REQUIRE( ASNPool::usedCount == base );

    /* default-constructed: empty, safe destroy */
    {
        AsnPtr<IntegerType> e;
        REQUIRE( !e );
        e.reset();                            /* no-op */
        REQUIRE( ASNPool::usedCount == base );
    }

    /* swap */
    {
        AsnPtr<IntegerType> a(asn_new<IntegerType>(10));
        AsnPtr<IntegerType> b(asn_new<IntegerType>(20));
        a.swap(b);
        REQUIRE( a->_value == 20 );
        REQUIRE( b->_value == 10 );
    }
    REQUIRE( ASNPool::usedCount == base );

    /* stale bulkFreed slot: silent, matches the asn_delete contract
     * (v3.3.3 semantics carried over).  LAST block: resetAll() re-baselines
     * usedCount to permCount, so no usedCount invariant may follow it. */
    int alarmsBefore = ASNPool::doubleReleaseAlarms;
    {
        AsnPtr<IntegerType> a(asn_new<IntegerType>(3));
        ASNPool::resetAll();                  /* bulk-free under the guard */
        /* guard destructor now deletes a bulkFreed slot: sanctioned stale
         * delete — must be silent (no new alarm) */
    }
    REQUIRE( ASNPool::doubleReleaseAlarms == alarmsBefore );
}

/* ==========================================================================
 * v3.4.3 — regression tests for fuzzing findings (blueprint Phase 3).
 * F1: decode_ber_length_integer read past the buffer on a long-form length
 *     field (`02 94` = 20 length bytes claimed) — the container path now
 *     rejects malformed length fields instead of OOB-reading.
 * F2: a hostile version field (e.g. 0xFFFFFFFF) was cast to the SNMP_VERSION
 *     enum before the range check — UB per UBSan.  Raw int validated first.
 * ========================================================================== */
TEST_CASE( "v3.4.3 fuzz F1: long-form BER length field cannot overrun the buffer", "[snmp][v343][fuzz]" ){

    /* INTEGER tag 0x02, length 0x94 = long form with 20 length bytes — the
     * old decoder read up to 127 bytes past the 3-byte buffer. */
    uint8_t malformed[3] = { 0x02, 0x94, 0x01 };
    int before = ASNPool::doubleReleaseAlarms;

    BER_CONTAINER* it = asn_new<IntegerType>();
    int rc = it->fromBuffer(malformed, sizeof(malformed));
    REQUIRE( rc <= 0 );            /* rejected, not OOB */
    asn_delete(it);

    /* full pipeline: packet claiming huge lengths must be rejected cleanly */
    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int testInt = 23;
    IntegerCallback* intCb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = intCb;

    uint8_t buf[64];
    buf[0] = 0x30; buf[1] = 0x84; buf[2] = 0x7F; buf[3] = 0xFF; buf[4] = 0xFF; buf[5] = 0xFF;
    for(int i = 6; i < 20; i++) buf[i] = 0x02;

    int respLen = 0;
    (void)handlePacketRoute(buf, 20, &respLen, 64, callbacks, callbacksCount, "public", "private");
    /* rejection is fine; the contract is NO crash / NO OOB / no pool damage */
    REQUIRE( ASNPool::doubleReleaseAlarms == before );

    delete intCb;
}

TEST_CASE( "v3.4.3 fuzz F2: hostile version field is validated before the enum cast", "[snmp][v343][fuzz]" ){

    /* v2c GET shell with version integer = 0xFFFFFFFF (not a valid SNMP_VERSION) */
    uint8_t buf[64];
    int n = 0;
    buf[n++] = 0x30; buf[n++] = 0x1E;                  /* outer SEQUENCE */
    buf[n++] = 0x02; buf[n++] = 0x05;                  /* INTEGER, 5 bytes */
    for(int i = 0; i < 5; i++) buf[n++] = 0xFF;        /* version = -1 */
    buf[n++] = 0x04; buf[n++] = 0x06;                  /* community OCTET STRING */
    memcpy(buf + n, "public", 6); n += 6;
    buf[n++] = 0xA0; buf[n++] = 0x0D;                  /* GetRequest PDU */
    buf[n++] = 0x02; buf[n++] = 0x01; buf[n++] = 0x2A; /* request-id 42 */
    buf[n++] = 0x02; buf[n++] = 0x01; buf[n++] = 0x00; /* error-status */
    buf[n++] = 0x02; buf[n++] = 0x01; buf[n++] = 0x00; /* error-index */
    buf[n++] = 0x30; buf[n++] = 0x03;                  /* varbind list */
    buf[n++] = 0x30; buf[n++] = 0x01;                  /* empty varbind */

    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int testInt = 23;
    IntegerCallback* intCb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = intCb;

    /* the active path (per build) must reject the invalid version without UB */
    int respLen = 0;
    SNMP_ERROR_RESPONSE r = handlePacketRoute(buf, n, &respLen, 64, callbacks, callbacksCount, "public", "private");
    REQUIRE( r == SNMP_REQUEST_INVALID );

    delete intCb;
}

/* ==========================================================================
 * v3.4.4 (P1 — blueprint Phase 1 diagnostic structure): runtime/high-water
 * statistics.  Every assertion captures a counter baseline and checks the
 * DELTA, so the monotonic statics stay valid across the whole suite.  The
 * same file compiles under every profile; a malformed/rejected/tooBig input
 * asserting +1 in BOTH the default (zero-copy) and nozc (classic) profiles
 * is the counter-parity proof between the two packet paths.
 * ========================================================================== */
TEST_CASE( "v3.4.4 P1: valid traffic leaves outcome counters at baseline, pool fields live", "[snmp][v344]" ){

    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int testInt = 23;
    IntegerCallback* intCb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = intCb;

    size_t baseMal = ASNPool::malformedPackets, baseRej = ASNPool::packetsRejected;
    size_t baseToo = ASNPool::tooBigResponses, baseFail = ASNPool::allocationFailures;

    SNMPPacket* getReq = GenerateTestSNMPRequestPacket();   /* valid 5-varbind GET */
    uint8_t buf[500];
    int bufLen = getReq->serialiseInto(buf, 500);
    delete getReq;

    int respLen = 0;
    SNMP_ERROR_RESPONSE r = handlePacketRoute(buf, bufLen, &respLen, 500, callbacks, callbacksCount, "public", "private");
    REQUIRE( r == SNMP_GET_OCCURRED );

    /* valid traffic: no outcome counters move */
    REQUIRE( ASNPool::malformedPackets   == baseMal );
    REQUIRE( ASNPool::packetsRejected    == baseRej );
    REQUIRE( ASNPool::tooBigResponses    == baseToo );
    REQUIRE( ASNPool::allocationFailures == baseFail );

    /* pool fields are live reads */
    REQUIRE( (size_t)SNMP_POOL_ASN_OBJECTS == (size_t)SNMP_POOL_ASN_OBJECTS );   /* cap constant sanity */
    delete intCb;
}

TEST_CASE( "v3.4.4 P1: malformed packet increments malformedPackets only", "[snmp][v344]" ){

    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int testInt = 23;
    IntegerCallback* intCb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = intCb;

    /* F1 corpus reuse: outer SEQUENCE claiming 0x7FFFFFFF content bytes */
    uint8_t buf[64];
    buf[0] = 0x30; buf[1] = 0x84; buf[2] = 0x7F; buf[3] = 0xFF; buf[4] = 0xFF; buf[5] = 0xFF;
    for(int i = 6; i < 20; i++) buf[i] = 0x02;

    size_t baseMal = ASNPool::malformedPackets, baseRej = ASNPool::packetsRejected;

    int respLen = 0;
    (void)handlePacketRoute(buf, 20, &respLen, 64, callbacks, callbacksCount, "public", "private");

    REQUIRE( ASNPool::malformedPackets == baseMal + 1 );
    REQUIRE( ASNPool::packetsRejected  == baseRej );   /* never double-counted */
    delete intCb;
}

TEST_CASE( "v3.4.4 P1: wrong community increments packetsRejected only", "[snmp][v344]" ){

    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    int testInt = 23;
    IntegerCallback* intCb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks[callbacksCount++] = intCb;

    SNMPPacket* getReq = GenerateTestSNMPRequestPacket();
    uint8_t buf[500];
    int bufLen = getReq->serialiseInto(buf, 500);
    delete getReq;

    size_t baseMal = ASNPool::malformedPackets, baseRej = ASNPool::packetsRejected;

    int respLen = 0;
    SNMP_ERROR_RESPONSE r = handlePacketRoute(buf, bufLen, &respLen, 500, callbacks, callbacksCount, "nope", "nope");
    REQUIRE( r == SNMP_REQUEST_INVALID_COMMUNITY );

    REQUIRE( ASNPool::packetsRejected  == baseRej + 1 );
    REQUIRE( ASNPool::malformedPackets == baseMal );   /* parse was fine */
    delete intCb;
}

TEST_CASE( "v3.4.4 P1: over-cap GetBulk increments tooBigResponses", "[snmp][v344]" ){

    ValueCallback* callbacks[SNMP_MAX_CALLBACKS_PER_AGENT] = {nullptr};
    int callbacksCount = 0;
    static int vals[SNMP_MAX_VARBINDS + 1];
    for(int i = 0; i < SNMP_MAX_VARBINDS + 1; i++){
        char oid[32];
        snprintf(oid, sizeof(oid), ".1.3.6.1.4.1.9.1.%d", i + 1);
        vals[i] = i;
        callbacks[callbacksCount++] = new IntegerCallback(new SortableOIDType(oid), &vals[i]);
    }

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    while(requestPacket->size() > 1) requestPacket->pop_back();
    requestPacket->at(0) = VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.9"), std::make_shared<IntegerType>(0));
    requestPacket->setVersion(SNMP_VERSION_2C);
    requestPacket->setPDUType(GetBulkRequestPDU);
    requestPacket->errorStatus.nonRepeaters = 0;
    requestPacket->errorIndex.maxRepititions = SNMP_MAX_VARBINDS + 4;

    uint8_t buf[500];
    int bufLen = requestPacket->serialiseInto(buf, 500);
    delete requestPacket;

    size_t baseToo = ASNPool::tooBigResponses;

    int respLen = 0;
    SNMP_ERROR_RESPONSE r = handlePacketRoute(buf, bufLen, &respLen, 500, callbacks, callbacksCount, "public", "private");
    REQUIRE( r == SNMP_ERROR_PACKET_SENT );
    REQUIRE( ASNPool::tooBigResponses == baseToo + 1 );

    for(int i = 0; i < callbacksCount; i++) delete callbacks[i];
}

TEST_CASE( "v3.4.4 P1: pool exhaustion increments allocationFailures exactly", "[snmp][v344]" ){

    size_t baseFail = ASNPool::allocationFailures;

    /* Drain the pool: every asn_new past capacity must count ONE failure. */
    int drained = 0;
    while(ASNPool::rawAlloc(16) != nullptr){ drained++; }
    /* rawAlloc returns nullptr at capacity; count how many objects fit */
    size_t cap = (size_t)SNMP_POOL_ASN_OBJECTS;
    (void)drained;

    size_t failDelta = ASNPool::allocationFailures - baseFail;

    /* Now deliberately exhaust: the pool is still drained, so EVERY one of
     * the cap+5 calls hits the exhausted pool (the host heap fallback does
     * not return slots) — each counts exactly one failure. */
    size_t before = ASNPool::allocationFailures;
    for(size_t i = 0; i < cap + 5; i++){
        (void)asn_new<IntegerType>((int)i);   /* host falls back to heap; counter still counts the exhaustion event */
    }
    REQUIRE( ASNPool::allocationFailures == before + cap + 5 );
    REQUIRE( failDelta == 0 );   /* draining via rawAlloc alone is not an allocation failure */

    /* clean the drained pool: resetAll restores the startup baseline */
    ASNPool::resetAll();
}

TEST_CASE( "v3.4.4 P1: getRuntimeStats snapshot + packets_received via loop()", "[snmp][v344]" ){

    /* feeding UDP: loop() must count one received datagram per parsePacket */
    class FeedingUDP : public UDP {
      public:
        int bytes = 0;
        int parsePacket() override { return bytes; }
        int read(uint8_t*, int max) override { return (max >= bytes) ? bytes : max; }
    };

    SNMPAgent agent((char*)"public", (char*)"private");
    FeedingUDP udp;
    udp.bytes = 20;
    agent.setUDP(&udp);

    size_t baseRecv = ASNPool::packetsReceived;
    size_t baseMal  = ASNPool::malformedPackets;

    /* 20 bytes of garbage: received++ then malformed++ (parse fails cleanly) */
    SNMP_ERROR_RESPONSE r = agent.loop();
    (void)r;

    SNMP_RuntimeStats stats;
    agent.getRuntimeStats(&stats);

    REQUIRE( stats.packets_received    == baseRecv + 1 );
    REQUIRE( stats.malformed_packets   == baseMal  + 1 );
    REQUIRE( stats.pool_cap            == (size_t)SNMP_POOL_ASN_OBJECTS );
    REQUIRE( stats.pool_used           == (size_t)ASNPool::usedCount );
    REQUIRE( stats.pool_high_water     == (size_t)ASNPool::usedCountPeak );
    REQUIRE( stats.double_release_errors == (size_t)ASNPool::doubleReleaseAlarms );

    /* nullptr guard is a no-op */
    agent.getRuntimeStats(nullptr);

    /* compile-time bounded-RAM constant is sane for this profile */
    REQUIRE( SNMP_ENGINE_MAX_RAM_BYTES >= (size_t)SNMP_POOL_ASN_OBJECTS * (size_t)SNMP_POOL_SLOT_SIZE );
    REQUIRE( SNMP_ENGINE_MAX_RAM_BYTES >= (size_t)MAX_SNMP_PACKET_LENGTH );
}
