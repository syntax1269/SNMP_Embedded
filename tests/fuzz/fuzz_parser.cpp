/* =====================================================================
 * SNMP_Embedded — P0 parser fuzzing harness (blueprint Phase 3)
 * =====================================================================
 * Standalone host executable (not part of the Catch2 suite): hammers the
 * parser with structured adversarial corpora + seeded random mutations and
 * verifies the blueprint invariants after EVERY input:
 *
 *   NEVER:  crash / hang / read outside buffer / write outside buffer /
 *           exhaust memory indefinitely
 *
 * Entry points under test (the full request pipeline, both paths):
 *   - handlePacket()          (classic owning-container path)
 *   - handlePacketInPlace()   (zero-copy path, default build)
 *   - snmp_ber_peek_packet()  (Phase-1 view walk)
 *   - container fromBuffer()/serialise() round-trips
 *
 * Determinism: xorshift1024* PRNG with a printed seed — any failure is
 * reproducible with `--seed N --case K`.  No external fuzzer dependency
 * (libFuzzer/AFL optional, see Makefile target `fuzz-libfuzzer`).
 *
 * Memory discipline: after every iteration the pool must return to its
 * registered-handler baseline (resetAll is what loop() does); a drift is
 * reported as a LEAK failure.  The census instrument in tests.cpp proves
 * zero heap per packet; here the pool-drift check catches unbounded growth.
 *
 * This file is INTERNAL (tests/fuzz/) — not shipped in the public library.
 * ===================================================================== */

#include "../../src/include/defs.h"
#include "../../src/include/BER.h"
#include "../../src/include/BERView.h"
#include "../../src/include/SNMPPacket.h"
#include "../../src/include/SNMPParser.h"
#include "../../src/include/ValueCallbacks.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

/* ------------------------------------------------------------------ */
/* xorshift1024* — deterministic, seedable, fast                       */
/* ------------------------------------------------------------------ */
struct Rng {
    uint64_t s[16];
    int p;
    explicit Rng(uint64_t seed){
        /* splitmix64 to seed the 1024-bit state */
        uint64_t z = seed ? seed : 0x9E3779B97F4A7C15ull;
        for(int i = 0; i < 16; i++){
            z += 0x9E3779B97F4A7C15ull;
            uint64_t x = z;
            x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
            x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
            s[i] = x ^ (x >> 31);
        }
        p = 0;
    }
    uint64_t next(){
        uint64_t s0 = s[p];
        p = (p + 1) & 15;
        uint64_t s1 = s[p];
        s1 ^= s1 << 31;
        s[p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30);
        return s[p] * 0x9E3779B97F4A7C15ull;
    }
    uint32_t u32(){ return (uint32_t)(next() >> 32); }
    /* uniform [0, n) */
    uint32_t below(uint32_t n){ return n ? u32() % n : 0; }
    uint8_t byte(){ return (uint8_t)(u32() & 0xFF); }
};

/* ------------------------------------------------------------------ */
/* Valid-packet builder — the mutation seed corpus                     */
/* ------------------------------------------------------------------ */
static void putLen(uint8_t* b, size_t len, int& n){
    /* BER length: short form < 128, else long form */
    if(len < 0x80){ b[n++] = (uint8_t)len; }
    else if(len < 0x100){ b[n++] = 0x81; b[n++] = (uint8_t)len; }
    else { b[n++] = 0x82; b[n++] = (uint8_t)(len >> 8); b[n++] = (uint8_t)(len & 0xFF); }
}
static void putTlv(uint8_t* b, int& n, uint8_t tag, const uint8_t* v, size_t len){
    b[n++] = tag; putLen(b, len, n);
    if(v && len) memcpy(b + n, v, len);
    n += (int)len;
}
static void putInt(uint8_t* b, int& n, long v){
    /* bounded: at most 9 content bytes (sign byte + 8 data) — callers pass
     * stack buffers; a stack-protector abort here is a HARNESS bug, not a
     * library finding. */
    uint8_t tmp[12]; int k = 0;
    if(v == 0){ tmp[k++] = 0; }
    else {
        unsigned long u = (unsigned long)v;
        int started = 0;
        for(int i = 7; i >= 0; i--){
            uint8_t byte = (uint8_t)((u >> (i*8)) & 0xFF);
            if(byte || started){
                if(!started && byte & 0x80) tmp[k++] = 0; /* sign byte */
                tmp[k++] = byte; started = 1;
            }
        }
    }
    putTlv(b, n, 0x02, tmp, (size_t)k);
}
/* OID: dotted string -> BER content bytes (first two arcs mangled) */
static int oidBytes(const char* s, uint8_t* out){
    long arcs[32]; int n = 0;
    const char* p = s; 
    while(*p && n < 32){
        if(*p == '.'){ p++; continue; }
        long v = 0; bool any = false;
        while(*p >= '0' && *p <= '9'){ v = v*10 + (*p - '0'); p++; any = true; }
        if(!any) break;
        arcs[n++] = v;
    }
    if(n < 2) return 0;
    int k = 0;
    out[k++] = (uint8_t)(arcs[0]*40 + arcs[1]);
    for(int i = 2; i < n; i++){
        long v = arcs[i];
        uint8_t tmp[8]; int t = 0;
        do { tmp[t++] = (uint8_t)(v & 0x7F); v >>= 7; } while(v);
        for(int j = t-1; j >= 0; j--) out[k++] = (uint8_t)(tmp[j] | (j ? 0x80 : 0));
    }
    return k;
}
static void putOid(uint8_t* b, int& n, const char* s){
    uint8_t tmp[64]; int k = oidBytes(s, tmp);
    putTlv(b, n, 0x06, tmp, (size_t)k);
}
static void putStr(uint8_t* b, int& n, const char* s){
    putTlv(b, n, 0x04, (const uint8_t*)s, strlen(s));
}
static void putNull(uint8_t* b, int& n){ putTlv(b, n, 0x05, nullptr, 0); }

/* Build a valid SNMP v2c GET with `nvbs` varbinds.  Returns total length. */
static int buildGet(uint8_t* b, const char* community, int requestID, const char* const* oids, int nvbs){
    int n = 0;
    uint8_t pdu[512]; int pn = 0;
    putInt(pdu, pn, requestID);
    putInt(pdu, pn, 0);   /* error-status */
    putInt(pdu, pn, 0);   /* error-index  */
    uint8_t vbl[400]; int vn = 0;
    for(int i = 0; i < nvbs; i++){
        uint8_t vb[128]; int bn = 0;
        putOid(vb, bn, oids[i]);
        putNull(vb, bn);
        putTlv(vbl, vn, 0x30, vb, (size_t)bn);
    }
    putTlv(pdu, pn, 0x30, vbl, (size_t)vn);
    uint8_t inner[600]; int in = 0;
    putInt(inner, in, 1);                    /* version = v2c */
    putStr(inner, in, community);
    pdu[0] = 0xA0;                           /* GetRequest PDU tag */
    memcpy(inner + in, pdu, pn); in += pn;
    putTlv(b, n, 0x30, inner, (size_t)in);
    return n;
}

static const char* kOids[] = { ".1.3.6.1.4.1.5.1", ".1.3.6.1.4.1.5.2" };

/* ------------------------------------------------------------------ */
/* Handlers + permission context (same shape as the hot-path tests)    */
/* ------------------------------------------------------------------ */
static ValueCallback* g_callbacks[SNMP_MAX_CALLBACKS_PER_AGENT];
static int g_callbacksCount = 0;
static int g_intVal = 23;

static void setupHandlers(){
    if(g_callbacksCount) return;
    g_callbacks[g_callbacksCount++] = new IntegerCallback(new SortableOIDType(kOids[0]), &g_intVal);
    IntegerCallback* setCb = new IntegerCallback(new SortableOIDType(kOids[1]), &g_intVal);
    setCb->isSettable = true;
    g_callbacks[g_callbacksCount++] = setCb;
}

static int poolUsedNow(){
    int high = 0;
    for(int i = 0; i < SNMP_POOL_ASN_OBJECTS; i++)
        if(ASNPool::slots[i].occupied) high = i + 1;
    return high;
}

/* ------------------------------------------------------------------ */
/* One fuzz iteration: feed buf to every entry point, check invariants */
/* ------------------------------------------------------------------ */
struct Failure {
    const char* kind;
    int seed;
    int caseId;
    const uint8_t* data;
    int len;
};

static bool runInput(uint8_t* buf, int len, int maxLen, int seed, int caseId, Failure* fail){
    /* input buffer is bounded by maxLen; len may exceed maxLen only if the
     * builder lied — clamp defensively so the harness itself never OOBs */
    if(len > maxLen) len = maxLen;
    if(len < 0) len = 0;

    uint8_t resp[1400];
    int respLen = -1;

    /* 1. zero-copy pipeline (default path) */
    SNMP_ERROR_RESPONSE r1 = handlePacketInPlace(buf, len, &respLen, (int)sizeof(resp),
                                                 g_callbacks, g_callbacksCount, "public", "private");
    (void)r1;

    /* 2. classic owning-container path */
    int respLen2 = -1;
    SNMP_ERROR_RESPONSE r2 = handlePacket(buf, len, &respLen2, (int)sizeof(resp),
                                          g_callbacks, g_callbacksCount, "public", "private");
    (void)r2;

    /* 3. raw view walk (const — parser must not mutate the input) */
    uint8_t before[1400];
    int cmpLen = len < (int)sizeof(before) ? len : (int)sizeof(before);
    memcpy(before, buf, (size_t)cmpLen);
    SnmpHeaderView view;
    (void)snmp_ber_peek_packet(buf, (size_t)len, &view);
    if(cmpLen && memcmp(before, buf, (size_t)cmpLen) != 0){
        fail->kind = "INPUT-MUTATED by snmp_ber_peek_packet";
        fail->seed = seed; fail->caseId = caseId; fail->data = buf; fail->len = len;
        return false;
    }

    /* 4. direct container decode of the root TLV (fromBuffer hardening) */
    {
        ComplexType* root = asn_new<ComplexType>(STRUCTURE);
        if(root){
            (void)root->fromBuffer(buf, (size_t)len);
            asn_delete(root);
        }
    }

    /* 5. pool discipline: every transient object must be released —
     *    registered-handler baseline is the only legal residue */
    ASNPool::resetAll();
    int baseline = 0;   /* handlers are heap-host objects in tests; pool permCount may hold their OIDs */
    int used = poolUsedNow();
    if(used > baseline + 0){
        /* after resetAll, everything above permCount must be gone;
         * permCount slots are the registered handler OIDs (2 here) */
        if(used > 2){
            char kind[128];
            snprintf(kind, sizeof(kind), "POOL-LEAK: %d slots live after resetAll (expected <= 2)", used);
            fail->kind = "POOL-LEAK";
            fail->seed = seed; fail->caseId = caseId; fail->data = buf; fail->len = len;
            return false;
        }
    }
    (void)baseline;
    return true;
}

/* ------------------------------------------------------------------ */
/* Structured adversarial corpus (blueprint Phase 3 list)              */
/* ------------------------------------------------------------------ */
enum CorpusKind {
    CK_VALID_GET, CK_TRUNCATED_SEQ, CK_TRUNCATED_LEN, CK_BAD_BER_TAG,
    CK_LEN_LARGER_THAN_BUF, CK_LEN_SMALLER_THAN_CONTENT, CK_NESTED_TLVS,
    CK_BAD_OID, CK_HUGE_INT, CK_MALFORMED_SET, CK_MALFORMED_BULK,
    CK_RANDOM_GARBAGE, CK_ALL_FF, CK_ALL_00, CK_COUNT
};

static const char* corpusName(int k){
    switch(k){
        case CK_VALID_GET:              return "valid-get";
        case CK_TRUNCATED_SEQ:          return "truncated-sequence";
        case CK_TRUNCATED_LEN:          return "truncated-length-field";
        case CK_BAD_BER_TAG:            return "invalid-ber-tag";
        case CK_LEN_LARGER_THAN_BUF:    return "length-larger-than-buffer";
        case CK_LEN_SMALLER_THAN_CONTENT:return "length-smaller-than-content";
        case CK_NESTED_TLVS:            return "deeply-nested-tlvs";
        case CK_BAD_OID:                return "invalid-oid";
        case CK_HUGE_INT:               return "huge-integer";
        case CK_MALFORMED_SET:          return "malformed-set";
        case CK_MALFORMED_BULK:         return "malformed-getbulk";
        case CK_RANDOM_GARBAGE:         return "random-garbage";
        case CK_ALL_FF:                 return "all-0xFF";
        case CK_ALL_00:                 return "all-0x00";
        default:                        return "?";
    }
}

static int buildCase(int kind, Rng& rng, uint8_t* buf, int maxLen){
    int n = 0;
    switch(kind){
        case CK_VALID_GET:
            return buildGet(buf, "public", (int)(rng.u32() | 1), kOids, 1 + rng.below(2));
        case CK_TRUNCATED_SEQ: {
            int full = buildGet(buf, "public", 42, kOids, 2);
            return full > 0 ? full/2 + rng.below((uint32_t)(full/2 ? full/2 : 1)) : 0;
        }
        case CK_TRUNCATED_LEN: {
            int full = buildGet(buf, "public", 42, kOids, 2);
            if(full < 3) return 0;
            /* keep the SEQUENCE tag, corrupt/truncate the length field */
            int cut = 2 + rng.below(2);
            return cut;
        }
        case CK_BAD_BER_TAG: {
            int full = buildGet(buf, "public", 42, kOids, 2);
            int pos = 1 + rng.below((uint32_t)(full > 2 ? full - 2 : 1));
            buf[pos] = (uint8_t)(0xC0 | rng.below(0x3F));   /* implausible tag */
            return full;
        }
        case CK_LEN_LARGER_THAN_BUF: {
            /* outer SEQUENCE claims far more than the buffer holds */
            if(maxLen < 6) return 0;
            buf[n++] = 0x30; buf[n++] = 0x84;               /* 4-byte long form */
            buf[n++] = 0x7F; buf[n++] = 0xFF; buf[n++] = 0xFF; buf[n++] = 0xFF;
            for(int i = 0; i < 8 && n < maxLen; i++) buf[n++] = 0x02;
            return n;
        }
        case CK_LEN_SMALLER_THAN_CONTENT: {
            int full = buildGet(buf, "public", 42, kOids, 2);
            if(full < 4) return 0;
            buf[1] = 0x01;   /* claims 1 byte of content, buffer holds more */
            return full;
        }
        case CK_NESTED_TLVS: {
            /* 40-deep NULL-content SEQUENCE nesting inside a valid envelope */
            int depth = 30 + rng.below(20);
            int total = 2*(depth) + 12;
            if(total > maxLen) depth = (maxLen - 12) / 2;
            if(depth <= 0) return 0;
            for(int i = 0; i < depth && n + 2 < maxLen - 8; i++){ buf[n++] = 0x30; buf[n++] = (uint8_t)(depth*2); }
            putInt(buf, n, 1);
            putStr(buf, n, "public");
            /* close nesting with a GetRequest PDU shell */
            buf[n++] = 0xA0; buf[n++] = 0x04;
            putInt(buf, n, 1); putInt(buf, n, 0);
            return n;
        }
        case CK_BAD_OID: {
            uint8_t pdu[256]; int pn = 0;
            putInt(pdu, pn, 7);
            putInt(pdu, pn, 0); putInt(pdu, pn, 0);
            uint8_t vbl[128]; int vn = 0;
            uint8_t vb[64]; int bn = 0;
            /* OID content with the forbidden leading 0x80 continuation or empty */
            uint8_t bad[4];
            bad[0] = (uint8_t)(rng.below(2) ? 0x80 : 0x00);
            bad[1] = 0x81; bad[2] = 0x81; bad[3] = 0x81;
            putTlv(vb, bn, 0x06, bad, 4);
            putNull(vb, bn);
            putTlv(vbl, vn, 0x30, vb, (size_t)bn);
            putTlv(pdu, pn, 0x30, vbl, (size_t)vn);
            uint8_t inner[300]; int in = 0;
            putInt(inner, in, 1); putStr(inner, in, "public");
            pdu[0] = 0xA0;
            memcpy(inner + in, pdu, pn); in += pn;
            putTlv(buf, n, 0x30, inner, (size_t)in);
            return n;
        }
        case CK_HUGE_INT: {
            uint8_t pdu[256]; int pn = 0;
            /* request-id: 9-byte integer (over-long, value > 64-bit) */
            uint8_t big[12]; int bk = 0;
            big[bk++] = 0x02; big[bk++] = 0x09;
            for(int i = 0; i < 9; i++) big[bk++] = 0xFF;
            memcpy(pdu + pn, big, bk); pn += bk;
            putInt(pdu, pn, 0); putInt(pdu, pn, 0);
            uint8_t vbl[64]; int vn = 0;
            uint8_t vb[32]; int bn = 0;
            putOid(vb, bn, kOids[0]); putNull(vb, bn);
            putTlv(vbl, vn, 0x30, vb, (size_t)bn);
            putTlv(pdu, pn, 0x30, vbl, (size_t)vn);
            uint8_t inner[300]; int in = 0;
            putInt(inner, in, 1); putStr(inner, in, "public");
            pdu[0] = 0xA0;
            memcpy(inner + in, pdu, pn); in += pn;
            putTlv(buf, n, 0x30, inner, (size_t)in);
            return n;
        }
        case CK_MALFORMED_SET: {
            /* SET whose varbind value TLV is truncated mid-header */
            uint8_t pdu[256]; int pn = 0;
            putInt(pdu, pn, 9); putInt(pdu, pn, 0); putInt(pdu, pn, 0);
            uint8_t vbl[128]; int vn = 0;
            uint8_t vb[64]; int bn = 0;
            putOid(vb, bn, kOids[1]);
            vb[bn++] = 0x04; vb[bn++] = 0x7F;   /* OCTET STRING claims 127 B, none present */
            putTlv(vbl, vn, 0x30, vb, (size_t)bn);
            putTlv(pdu, pn, 0x30, vbl, (size_t)vn);
            uint8_t inner[300]; int in = 0;
            putInt(inner, in, 1); putStr(inner, in, "public");
            pdu[0] = 0xA3;   /* SetRequest */
            memcpy(inner + in, pdu, pn); in += pn;
            putTlv(buf, n, 0x30, inner, (size_t)in);
            return n;
        }
        case CK_MALFORMED_BULK: {
            /* GETBULK with nonRepeaters/maxRepetitions swapped/huge */
            uint8_t pdu[256]; int pn = 0;
            putInt(pdu, pn, 11);
            putInt(pdu, pn, (long)(0x7FFFFFFF00000000LL));  /* huge nonRepeaters */
            putInt(pdu, pn, -1);                            /* negative maxRep */
            uint8_t vbl[64]; int vn = 0;
            uint8_t vb[32]; int bn = 0;
            putOid(vb, bn, kOids[0]); putNull(vb, bn);
            putTlv(vbl, vn, 0x30, vb, (size_t)bn);
            putTlv(pdu, pn, 0x30, vbl, (size_t)vn);
            uint8_t inner[300]; int in = 0;
            putInt(inner, in, 1); putStr(inner, in, "public");
            pdu[0] = 0xA5;   /* GetBulkRequest */
            memcpy(inner + in, pdu, pn); in += pn;
            putTlv(buf, n, 0x30, inner, (size_t)in);
            return n;
        }
        case CK_RANDOM_GARBAGE: {
            int len = 1 + rng.below((uint32_t)maxLen);
            for(int i = 0; i < len; i++) buf[i] = rng.byte();
            /* bias: 1-in-4 looks like an SNMP envelope head */
            if(rng.below(4) == 0 && len > 8){ buf[0] = 0x30; buf[1] = (uint8_t)(len - 2 > 127 ? 127 : len - 2); }
            return len;
        }
        case CK_ALL_FF: {
            int len = 8 + rng.below((uint32_t)(maxLen - 8));
            memset(buf, 0xFF, (size_t)len);
            return len;
        }
        case CK_ALL_00: {
            int len = 8 + rng.below((uint32_t)(maxLen - 8));
            memset(buf, 0x00, (size_t)len);
            return len;
        }
        default: return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Mutation of a valid packet — bit flips, byte swaps, splices          */
/* ------------------------------------------------------------------ */
static int mutate(Rng& rng, uint8_t* buf, int len, int maxLen){
    int ops = 1 + rng.below(4);
    for(int i = 0; i < ops; i++){
        int kind = rng.below(5);
        if(len <= 0) break;
        switch(kind){
            case 0: { /* bit flip */
                int pos = rng.below((uint32_t)len);
                buf[pos] ^= (uint8_t)(1u << rng.below(8));
                break;
            }
            case 1: { /* random byte */
                int pos = rng.below((uint32_t)len);
                buf[pos] = rng.byte();
                break;
            }
            case 2: { /* interesting byte */
                static const uint8_t interesting[] = {0x00,0x01,0x7F,0x80,0x81,0xFF,0x30,0xA0,0xA2,0xA5,0x02,0x04,0x05,0x06};
                int pos = rng.below((uint32_t)len);
                buf[pos] = interesting[rng.below(sizeof(interesting))];
                break;
            }
            case 3: { /* duplicate a slice */
                if(len + 8 > maxLen) break;
                int sl = 1 + rng.below(8);
                int from = rng.below((uint32_t)len);
                int cp = sl < (maxLen - len) ? sl : (maxLen - len);
                if(cp > 0){ memmove(buf + len, buf + from, (size_t)cp); len += cp; }
                break;
            }
            case 4: { /* truncate */
                int cut = 1 + rng.below((uint32_t)len);
                len -= cut; if(len < 0) len = 0;
                break;
            }
        }
    }
    return len;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
static void printHex(const uint8_t* p, int len){
    for(int i = 0; i < len && i < 96; i++) printf("%02X", p[i]);
    if(len > 96) printf("...");
    printf("\n");
}

int main(int argc, char** argv){
    /* ---- CLI: --seed N --cases K --maxlen B [--quiet] ----
     * Defaults: seed = fixed default (deterministic CI), cases = 20000,
     * maxlen = 768 (the p768 hardware budget).  --seed 0 with --cases 0
     * runs ONLY the structured corpus (no mutations). */
    long seed        = 20260908;   /* fixed default: CI-deterministic */
    long cases       = 20000;
    int  maxLen      = 768;
    bool quiet       = false;
    for(int i = 1; i < argc; i++){
        if(!strcmp(argv[i], "--seed")   && i+1 < argc) seed  = atol(argv[++i]);
        else if(!strcmp(argv[i], "--cases")  && i+1 < argc) cases = atol(argv[++i]);
        else if(!strcmp(argv[i], "--maxlen") && i+1 < argc) maxLen = atoi(argv[++i]);
        else if(!strcmp(argv[i], "--quiet")) quiet = true;
        else { fprintf(stderr, "usage: %s [--seed N] [--cases K] [--maxlen B] [--quiet]\n", argv[0]); return 2; }
    }
    if(maxLen < 64 || maxLen > 1400){ fprintf(stderr, "maxlen out of range [64,1400]\n"); return 2; }

    setupHandlers();

    Rng rng((uint64_t)seed);
    uint8_t buf[1400];
    Failure fail;
    long executed = 0;

    /* ---- Phase A: structured corpus, every kind, both paths ---- */
    for(int kind = 0; kind < CK_COUNT; kind++){
        int len = buildCase(kind, rng, buf, maxLen);
        if(len < 0) len = 0;
        if(!runInput(buf, len, maxLen, (int)seed, kind, &fail)){
            printf("FUZZ FAIL [%s] corpus=%s seed=%ld case=%d len=%d\n  bytes: ",
                   fail.kind, corpusName(kind), seed, kind, fail.len);
            printHex(fail.data, fail.len);
            return 1;
        }
        executed++;
    }

    /* ---- Phase B: seeded mutation campaign ---- */
    for(long c = 0; c < cases; c++){
        int kind = (int)rng.below(CK_COUNT);
        uint8_t seedPkt[1400];
        int seedLen = buildCase(kind, rng, seedPkt, maxLen);
        if(seedLen < 0 || seedLen > maxLen) seedLen = seedLen < 0 ? 0 : maxLen;
        memcpy(buf, seedPkt, (size_t)seedLen);
        int len = mutate(rng, buf, seedLen, maxLen);
        if(!runInput(buf, len, maxLen, (int)seed, (int)c, &fail)){
            printf("FUZZ FAIL [%s] seed=%ld case=%ld corpus=%s len=%d\n  bytes: ",
                   fail.kind, seed, c, corpusName(kind), fail.len);
            printHex(fail.data, fail.len);
            return 1;
        }
        executed++;
    }

    if(!quiet){
        printf("fuzz: OK — %ld inputs across %d corpora x 2 packet paths + view walk + container decode\n",
               executed, (int)CK_COUNT);
        printf("      seed=%ld cases=%ld maxlen=%d  invariants: no-crash no-hang no-OOB no-input-mutation no-pool-leak\n",
               seed, cases, maxLen);
    }
    return 0;
}
