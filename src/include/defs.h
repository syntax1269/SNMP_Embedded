/* -------------------------------------------------------------------------- *
 * USER-TUNEABLE COMPILE-TIME CONSTANTS (override BEFORE including this file)
 *
 *   To change any of these values from library default, do this in your .ino:
 *
 *       #define SNMP_MAX_COMPLEX_CHILDREN        8
 *       #define SNMP_POOL_ASN_OBJECTS           32
 *       // ... etc ...
 *       #include <SNMP_Embedded.h>
 *
 *   Because each constant below is guarded with `#ifndef ... #endif`, the
 *   user's earlier #define in the sketch (or via -D on the compiler command
 *   line, or via build_flags in platformio.ini) will be used instead of the
 *   library default listed here.
 *
 *   Good targets to reduce for ESP8266 1MB / 80KB RAM sensor builds:
 *       SNMP_POOL_ASN_OBJECTS      64 -> 32    (-24,576 B BSS)
 *       SNMP_POOL_VARBIND_OBJECTS  32 -> 12
 *       SNMP_MAX_CALLBACKS_PER_AGENT 64 -> 16
 *       SNMP_MAX_VARBINDS          16 -> 4
 *       SNMP_MAX_COMPLEX_CHILDREN  16 -> 8
 *       SNMP_MAX_TRAPS_INFLIGHT     8 -> 4
 * -------------------------------------------------------------------------- */

#ifndef SNMP_DEFS_h
#define SNMP_DEFS_h

#include <stdint.h>

/* v3.3.4: define SNMP_NO_BUILTIN_SYSUPTIME (global build flag / sketch define
 * BEFORE including SNMP_Embedded.h) to remove the library-registered dynamic
 * sysUpTime handler (reclaims exactly 1 pool slot). With the flag, sysUpTime
 * becomes a normal OID the sketch may register itself. */

#ifndef DEBUG
    #define DEBUG           0       /* 0  or  1  or  2 */
#endif

#define LIBRARY_VERSION_MAJOR 3
#define LIBRARY_VERSION_MINOR 3
#define LIBRARY_VERSION_PATCH 4
#define LIBRARY_VERSION "3.3.4"

typedef enum SNMP_ERROR_RESPONSE {
    SNMP_NO_UDP = -10,
    SNMP_REQUEST_TOO_LARGE = -5,
    SNMP_REQUEST_INVALID = -4,
    SNMP_REQUEST_INVALID_COMMUNITY = -3,
    SNMP_FAILED_SERIALISATION = -2,
    SNMP_GENERIC_ERROR = -1,
    SNMP_NO_PACKET = 0,
    SNMP_NO_ERROR = 1,
    SNMP_GET_OCCURRED = 2,
    SNMP_GETNEXT_OCCURRED = 3,
    SNMP_GETBULK_OCCURRED = 4,
    SNMP_SET_OCCURRED = 5,
    SNMP_ERROR_PACKET_SENT = 6, // A packet indicating that an error occurred was sent
    SNMP_INFORM_RESPONSE_OCCURRED = 7,
    SNMP_UNKNOWN_PDU_OCCURRED = 8
} SNMP_ERROR_RESPONSE;

typedef unsigned long snmp_request_id_t;

#define INVALID_SNMP_REQUEST_ID 0


typedef enum SnmpVersionEnum {
    SNMP_VERSION_1,
    SNMP_VERSION_2C,
    SNMP_VERSION_MAX
} SNMP_VERSION;

typedef enum {
     SNMP_PERM_NONE,
     SNMP_PERM_READ_ONLY,
     SNMP_PERM_READ_WRITE
} SNMP_PERMISSION;

extern const char* SNMP_TAG;


/* -------------------------------------------------------------------------- *
 * PLATFORM AUTO-TUNE (ESP8266)
 *
 *   On ESP8266 (80 KB DRAM typical, hard 64-80 KB BSS budget once WiFi
 *   libraries are loaded) the library defaults below would otherwise
 *   overflow RAM for any sketch that also uses WiFi + a filesystem.
 *   Enable ESP8266_TINY to swap in conservative BSS values (~ -28 KB
 *   vs generic defaults).  Set SNMP_SKIP_ESP8266_AUTOTUNE to 1 before
 *   including this file if you want full control on ESP8266 too.
 * -------------------------------------------------------------------------- */
#if defined(ESP8266) && !defined(SNMP_SKIP_ESP8266_AUTOTUNE)
    #define _SNMP_ESP8266_TINY  1
#endif

#ifndef MAX_SNMP_PACKET_LENGTH
  #ifdef _SNMP_ESP8266_TINY
    #define MAX_SNMP_PACKET_LENGTH  1024
  #else
    #define MAX_SNMP_PACKET_LENGTH  1400
  #endif
#endif
#ifndef OCTET_TYPE_MAX_LENGTH
  /* OctetType/OpaqueType internal fixed buffer length.  256 B covers 99% of
     MIB string columns (sysDescr is typically ~120 B, ifDescr ~64 B, etc.).
     Sketch-side override: #define OCTET_TYPE_MAX_LENGTH 500 BEFORE including
     SNMP_Embedded.h for endpoints that need to serve 500 B MIB strings. */
  #define OCTET_TYPE_MAX_LENGTH      256
#endif

#ifndef SNMP_MAX_COMMUNITY_LEN
    /* RFC 3418 §2.6 SNMPv2c community strings are traditionally short tokens;
       32 B is the practical RFC ceiling.  Users who need legacy long strings
       (e.g. v3-style views over v2c) can #define SNMP_MAX_COMMUNITY_LEN 64
       BEFORE including SNMP_Embedded.h — value is guarded so sketch-side wins. */
    #define SNMP_MAX_COMMUNITY_LEN   32
#endif
#ifndef SNMP_MAX_OID_STR_LEN
  #ifdef _SNMP_ESP8266_TINY
    #define SNMP_MAX_OID_STR_LEN     192
  #else
    #define SNMP_MAX_OID_STR_LEN     256
  #endif
#endif
#ifndef SNMP_MAX_STRING_LEN
    #define SNMP_MAX_STRING_LEN      OCTET_TYPE_MAX_LENGTH
#endif

#ifndef SNMP_MAX_OID_SUBIDENTIFIERS
    #define SNMP_MAX_OID_SUBIDENTIFIERS    32   /* BER-encoded OID: max 32 sub-IDs  =>  32 bytes w/ header byte.
                                                   Real-world: "1.3.6.1.4.1.318.1.1.27.3.2.7.1.7.2.1001" = 17 sub-IDs.
                                                   32 is 2x safe.  Used to size OIDType::data fixed buffer. */
#endif
#ifndef SNMP_MAX_COMPLEX_CHILDREN
  #ifdef _SNMP_ESP8266_TINY
    #define SNMP_MAX_COMPLEX_CHILDREN      16
  #else
    #define SNMP_MAX_COMPLEX_CHILDREN      24   /* Maximum children inside a single BER ComplexType (STRUCTURE / PDU / VarBindList).
                                                   Real-world GetResponses contain < 8 VarBinds; 16 covers bulkwalk default=10 + some slack.
                                                   24 (default) / 16 (ESP8266_TINY) safely accommodates GetBulk + walk response envelopes.
                                                   Used to size ComplexType::values[] fixed array. */
  #endif
#endif
/* =====================================================================
 *  v3.3.2 — PACKET SIZE IS THE CONTROLLING AUTHORITY
 *  ---------------------------------------------------------------------
 *  No RFC dictates a varbind count (RFC 3416 max-bindings = 2^31-1); the
 *  real constraint is the agent's own serialization buffer.  The varbind
 *  cap is therefore DERIVED from MAX_SNMP_PACKET_LENGTH, so the cap can
 *  never promise a response that cannot physically be serialized:
 *
 *      MAXVB = (MAX_SNMP_PACKET_LENGTH - SNMP_PACKET_FIXED_OVERHEAD)
 *              / SNMP_WORST_CASE_VARBIND_BYTES
 *
 *  Per-varbind worst case is dominated by the OID string: TINY permits
 *  SNMP_MAX_OID_STR_LEN=192 -> an OID container of that length occupies
 *  192+3=195 B on the wire; ~36 B covers a max value container + VarBind/
 *  VBList/PDU envelopes + community/version header share.  TINY 1024:
 *  (1024-40)/160 = 6.15 -> floor 6, EXACTLY the campaign-proven TINY cap.
 *  Generic 1400: (1400-40)/160 = 8.5 -> floor 8 (was 16 — the old value
 *  predated the 192-B OID budget; it promised varbinds the buffer could
 *  not serialize, which is what the v3.3.2 fit guard now backstops).
 *  User override via -DSNMP_MAX_VARBINDS=n still wins (the ifndef below).
 * ===================================================================== */
#ifndef SNMP_PACKET_FIXED_OVERHEAD
  #define SNMP_PACKET_FIXED_OVERHEAD   40   /* SEQUENCE headers + version + community + PDU envelope + request-id/error fields */
#endif
#ifndef SNMP_WORST_CASE_VARBIND_BYTES
  #define SNMP_WORST_CASE_VARBIND_BYTES  160 /* full-length OID string + BER headers + max value container + VB/VBList share */
#endif
#ifndef SNMP_MAX_VARBINDS
  #define SNMP_MAX_VARBINDS  ( (MAX_SNMP_PACKET_LENGTH - SNMP_PACKET_FIXED_OVERHEAD) / SNMP_WORST_CASE_VARBIND_BYTES )
#endif
/* Compile-time guarantee: a CAP-MAX response of worst-case varbinds fits
 * the packet buffer.  Catches user overrides (-D pairs) that break the
 * invariant the derivation enforces by default. */
static_assert( (SNMP_MAX_VARBINDS * SNMP_WORST_CASE_VARBIND_BYTES + SNMP_PACKET_FIXED_OVERHEAD) <= MAX_SNMP_PACKET_LENGTH,
               "SNMP_MAX_VARBINDS override: cap-max worst-case response would exceed MAX_SNMP_PACKET_LENGTH - lower the varbind cap or raise the packet size");
#ifndef SNMP_MAX_CALLBACKS_PER_AGENT
  #ifdef _SNMP_ESP8266_TINY
    #define SNMP_MAX_CALLBACKS_PER_AGENT   24
  #else
    #define SNMP_MAX_CALLBACKS_PER_AGENT   64   /* Maximum OID handlers registered per SNMPAgent instance.  Large sensor deployments
                                                   have ~32; 64 covers a device exposing every numeric column of a 30-row table. */
  #endif
#endif

/* v3.3.4: the built-in dynamic sysUpTime registration counts against the same
 * derived-sizing budget as every other handler — it is an ordinary
 * addDynamicReadOnlyTimestampHandler() call, so the pool math picks it up
 * automatically. Compile-time footprint pins (default +1, opt-out +0) below. */
#ifndef SNMP_NO_BUILTIN_SYSUPTIME
  #define SNMP_HAS_BUILTIN_SYSUPTIME 1
  static_assert(SNMP_MAX_CALLBACKS_PER_AGENT >= 1,
                "SNMP_MAX_CALLBACKS_PER_AGENT must be >= 1 to hold the built-in sysUpTime handler (define SNMP_NO_BUILTIN_SYSUPTIME to opt out)");
#else
  #define SNMP_HAS_BUILTIN_SYSUPTIME 0
#endif
#ifndef SNMP_MAX_AGENTS
    #define SNMP_MAX_AGENTS                  2   /* Concurrent SNMPAgent instances.  ESP8266 almost always 1; 2 allows dual-interface. */
#endif
#ifndef SNMP_MAX_UDP_PER_AGENT
    #define SNMP_MAX_UDP_PER_AGENT           2   /* Maximum UDP interfaces bound per single SNMPAgent (e.g. WiFi + Ethernet on ESP32). */
#endif
#ifndef SNMP_MAX_TRAPS_INFLIGHT
  #ifdef _SNMP_ESP8266_TINY
    #define SNMP_MAX_TRAPS_INFLIGHT          4
  #else
    #define SNMP_MAX_TRAPS_INFLIGHT          8   /* Maximum outstanding InformItem messages queued for retry.  ESP8266 real-world hard cap. */
  #endif
#endif
#ifndef SNMP_MAX_CALLBACKS_PER_TRAP
  #ifdef _SNMP_ESP8266_TINY
    #define SNMP_MAX_CALLBACKS_PER_TRAP      8
  #else
    #define SNMP_MAX_CALLBACKS_PER_TRAP     16   /* Maximum OIDs / VBs in a single SNMPTrap.  Typical trap payload < 8 VBs. */
  #endif
#endif

/* =====================================================================
 *  DERIVED POOL SIZING
 *  ---------------------------------------------------------------------
 *  The ASN pool auto-sizes from the flags the sketch already sets,
 *  instead of a fixed 76/80 that assumes a ~23-handler deployment:
 *
 *      pool = WORST_TICK_TRANSIENTS  (from caps below, at full concurrency)
 *           + SNMP_MAX_CALLBACKS_PER_AGENT  (the sketch's declared OID count;
 *             each handler contributes a permanent OID + value object that
 *             must survive resetAll() — the frozen permanent baseline)
 *
 *  WORST_TICK_TRANSIENTS = CAP+2 (GetBulk response at the varbind cap,
 *  each VB = OID + value + VarBind envelope, plus PDU/VarBindList
 *  envelopes) + IF*3 (traps: envelope + OID + value each, decoded while a
 *  response is being built) + VB*6 (walk-chain reserve + parse headroom,
 *  proportional to request width).
 *
 *  PROVENANCE OF THE MARGIN (v3.3.3): the original +24 flat term came from
 *  MEASURED worst ticks on ESP8266 (usedCountPeak 66 at TINY caps under
 *  sustained Cr6-walk + SET saturation with trap concurrency; the 23-handler
 *  campaign peaked 75/76 — one slot from exhaustion).  Four further 5-minute
 *  200 ms floods at the 768-B profile (VB=4) peaked at 51 with a 15-slot
 *  margin — over-provisioned for this workload class — so the flat +24 was
 *  redistributed into width-proportional terms (8*VB + 3*IF), which is
 *  algebraically identical at the proven TINY caps (VB6/IF4 -> 60) and
 *  tighter below them (VB4/IF4 -> 44 -> pool 56 at 12 handlers = peak 51 +
 *  margin 5).
 *
 *  v3.3.2: SNMP_MAX_VARBINDS is itself derived from MAX_SNMP_PACKET_LENGTH
 *  (see the derivation above), so packet size transitively sizes the pool:
 *  TINY 1024 -> cap 6 -> transients 60 (unchanged, hardware-proven).
 *
 *  TINY defaults (caps 6/4/8, callbacks 24) derive pool 84 — 18-slot
 *  margin over the measured peak 66. A sketch declaring 12 handlers
 *  derives 72.  At the 768-B profile a 12-handler sketch derives 56
 *  (flood-proven: peak 51, margin 5). Sketches with MORE handlers
 *  automatically get MORE pool (a 40-handler deployment derives 100; the old
 *  fixed 76 starved it).  Sketch-side SNMP_POOL_ASN_OBJECTS #define still
 *  wins (override).  Floor: SNMP_POOL_ASN_OBJECTS >= 24 static_assert
 *  unchanged, plus the transient+12-handler guard below.
 *
 *  !! SIZE OVERRIDES AND THE ONE-DEFINITION RULE !!
 *  SNMP_MAX_CALLBACKS_PER_AGENT (and any size-affecting flag: OCTET_TYPE_MAX_LENGTH,
 *  SNMP_MAX_OID_STR_LEN, SNMP_POOL_*) changes CLASS LAYOUT (callbacks[], container
 *  buffers, slot geometry). Overriding it in the sketch TU only (a #define before
 *  #include) desynchronizes the sketch's view of SNMPAgent/BER objects from the
 *  library's compiled TUs -> undefined behavior. Observed live on ESP8266: instant
 *  reboot loop. ALWAYS set these via GLOBAL build flags (-D on platformio.ini
 *  build_flags / arduino-cli --build-flags) so every TU agrees.
 * ===================================================================== */
#ifndef SNMP_WORST_TICK_TRANSIENTS
  /* v3.3.3: flood-calibrated margin, piecewise on request width.
   *  3*IF      traps in flight (envelope + OID + value each)
   *  VB<=6:    8*VB — flood-calibrated narrow profile.  Four 5-minute
   *            200 ms-period floods at the 768-B profile (VB=4) peaked at
   *            usedCount 51 -> pool 56 at 12 handlers = margin 5.  VB6 ->
   *            60, the hardware-proven TINY value, UNCHANGED
   *            (measured peak 66 -> pool 72 at 12 handlers, margin 6).
   *  VB>6:     3*(VB+2)+24 — the response+headroom terms for wide profiles,
   *            UNCHANGED, so generic profiles neither grow nor shrink
   *            (VB8/IF8 -> 78; any larger override, e.g. VB16/IF8 -> 102,
   *            as proven across the reliability campaign).
   *  Net effect: only builds narrower than the proven TINY cap tighten. */
  #define SNMP_WORST_TICK_TRANSIENTS  ( (SNMP_MAX_TRAPS_INFLIGHT) * 3 \
      + ( ((SNMP_MAX_VARBINDS) <= 6) ? (SNMP_MAX_VARBINDS) * 8 : ( (SNMP_MAX_VARBINDS) + 2 ) * 3 + 24 ) )
#endif
#ifndef SNMP_POOL_ASN_OBJECTS
  #define SNMP_POOL_ASN_OBJECTS  ( SNMP_WORST_TICK_TRANSIENTS + SNMP_MAX_CALLBACKS_PER_AGENT )
#endif
/* SNMP_POOL_LOCK_AT_BOOT = 1 (default) makes every SNMPAgent constructor
 * pre-allocate the whole ASN pool arena at global-constructor time — before
 * setup(), before WiFi — when the ESP8266/ESP32 heap is pristine. One
 * contiguous sizeof(Slot)*SNMP_POOL_ASN_OBJECTS block is trivially available
 * then; the same request at first-parse time (lazy allocation) can fail
 * after other libraries have fragmented the heap, and on ESP8266 (exceptions
 * disabled) a failed new aborts the sketch mid-service. Allocation size is
 * still fixed at compile time; lock-in only moves WHEN the one-shot happens.
 * Failed lock-in (heap already exhausted at ctor time) is logged and falls
 * back to the lazy path — no behaviour regression. No ODR impact: this flag
 * does not change any class layout, so per-TU overrides are safe (but global
 * build flags remain the recommended style for all size flags).
 * 0 restores lazy first-use allocation. */
#ifndef SNMP_POOL_LOCK_AT_BOOT
  #define SNMP_POOL_LOCK_AT_BOOT 1
#endif

#ifndef SNMP_POOL_VARBIND_OBJECTS
  #ifdef _SNMP_ESP8266_TINY
    #define SNMP_POOL_VARBIND_OBJECTS       24
  #else
    #define SNMP_POOL_VARBIND_OBJECTS       32   /* Global placement-pool slot count for transient VarBind objects. */
  #endif
#endif

/* SNMP_POOL_SLOT_SIZE is the raw payload size of each ASNPool::Slot.
 * Each slot must fit the LARGEST concrete BER subclass we instantiate.
 * Right-sized to the MEASURED sizeof() of the largest container
 * (host sizeof probe, Xtensa-compatible layout):
 *   TINY   config: OctetType = 288 B (_value[256] + base)  -> slot 288
 *   default config: OIDType/SortableOIDType = 312 B         -> slot 312
 * Oversized slots pad every object with dead bytes (~44% of the arena —
 * 17 KB of the ESP8266's 39.5 KB pool was padding). static_assert
 * guards in BER.h now pin every container <= slot so this can never
 * silently go stale again; a sketch raising OCTET_TYPE_MAX_LENGTH or
 * SNMP_MAX_OID_STR_LEN gets a compile error instead of a runtime
 * placement failure. */
#ifndef SNMP_POOL_SLOT_SIZE
  #ifdef _SNMP_ESP8266_TINY
    #define SNMP_POOL_SLOT_SIZE 288
  #else
    #define SNMP_POOL_SLOT_SIZE 312
  #endif
#endif

/* =====================================================================
 *  COMPILE-TIME POOL FLOOR GUARDS
 *  ---------------------------------------------------------------------
 *  Minimum-safe values empirically proven on ESP8266 (ESP8266EX, 80 MHz,
 *  80 KB RAM, CH340 USB).  Anything BELOW these caused a NULL-pointer
 *  dereference crash (Exception 28 on Xtensa) the INSTANT the first UDP
 *  GetRequest arrived on port 161.  Root cause: ASNPool::alloc() or
 *  VarBind pool returned nullptr on exhaustion, or callbacks[] array
 *  overflow (23 handlers into 20-slot array) silently corrupted the
 *  adjacent UDP pointer/cbCount members → SNMP socket went deaf.
 *
 *  Full incident analysis: repo test suite (tests/tests.cpp) + the
 *  upstream-fork reliability campaign documentation.
 *  =====================================================================
 */
#if defined(__cplusplus)

    #define SNMP_FLOOR_MSG_HEAD \
        "\n[SNMP_Embedded compile guard] Pool cap below empirically-proven minimum." \
        "\n  Smaller values cause NULL allocation or silent array overflow on first " \
        "\n  inbound SNMP packet → ESP8266 Exception 28 / hard fault." \
        "\n  Full analysis: host test suite + reliability campaign notes."

    /* Floor of 8: the original 24 guarded against the
     * SILENT callbacks[] overflow of early revisions;
     * addHandler() now rejects overflow loudly (LOGE + nullptr) and the pool
     * DERIVES from this value, so a small honest declaration is both safe and
     * the whole point of derived sizing. Must stay >= the handlers the sketch
     * actually registers, else registration fails at runtime with guidance. */
    static_assert(SNMP_MAX_CALLBACKS_PER_AGENT >= 8,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> SNMP_MAX_CALLBACKS_PER_AGENT must be >= 8. Set it to the number of"
        "\n     handlers your sketch registers (addXxxHandler calls); over-capacity"
        "\n     registration is rejected loudly at runtime. The ASN pool auto-sizes"
        "\n     from this value.");

    static_assert(SNMP_POOL_ASN_OBJECTS >= (int)SNMP_WORST_TICK_TRANSIENTS,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> SNMP_POOL_ASN_OBJECTS must cover the transient burst alone"
        "\n     (SNMP_WORST_TICK_TRANSIENTS). Your override starves the response/"
        "\n     trap path of every slot it needs at the configured varbind/trap"
        "\n     caps - handler slots live ON TOP of this (see the formula above).");

    static_assert(SNMP_POOL_ASN_OBJECTS >= 24,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> SNMP_POOL_ASN_OBJECTS must be >= 24."
        "\n     With 16: GetRequest BER parse ran dry before GetResponse was encoded,"
        "\n     crashing at excvaddr=0x2C (nullptr + 44 bytes) inside handlePacket().");

    static_assert(SNMP_POOL_VARBIND_OBJECTS >= 8,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> SNMP_POOL_VARBIND_OBJECTS must be >= 8."
        "\n     With 4: request + response VB lifetimes overlap → NULL deref.");

    static_assert(SNMP_MAX_COMPLEX_CHILDREN >= 6,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> SNMP_MAX_COMPLEX_CHILDREN must be >= 6."
        "\n     Absolute minimum for a v2c PDU wrapper (4 children + vb_list + headroom).");

    static_assert(SNMP_MAX_VARBINDS >= 4,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> SNMP_MAX_VARBINDS must be >= 4."
        "\n     (ESP8266_TINY default is 6; 4 is rock-bottom for a GET pair.)");

    static_assert(MAX_SNMP_PACKET_LENGTH >= 512,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> MAX_SNMP_PACKET_LENGTH must be >= 512 bytes."
        "\n     RFC 3417 sets 484 as the historic floor; 512 safely covers snmpwalk"
        "\n     responses with 12 varbinds plus PDU headers.  ESP8266 default 1024.");

    static_assert(OCTET_TYPE_MAX_LENGTH >= 64,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> OCTET_TYPE_MAX_LENGTH must be >= 64."
        "\n     sysContact/Name/Location in RFC1213 use 64-byte buffers minimum.");

    static_assert(SNMP_MAX_OID_SUBIDENTIFIERS >= 16,
        SNMP_FLOOR_MSG_HEAD
        "\n  -> SNMP_MAX_OID_SUBIDENTIFIERS must be >= 16."
        "\n     enterprises.99999.1.14 = 12 sub-IDs.  16 is 33% headroom minimum.");

    #undef SNMP_FLOOR_MSG_HEAD

#endif

#define SNMP_ERROR_OK 1

#define SNMP_PACKET_PARSE_ERROR_OFFSET -20
#define SNMP_BUFFER_PARSE_ERROR_OFFSET -10
#define SNMP_BUFFER_ENCODE_ERROR_OFFSET -30

typedef enum ERROR_STATUS_WITH_VALUE {
    // V1 Errors
    NO_ERROR = 0,
    TOO_BIG = 1,
    NO_SUCH_NAME = 2,
    BAD_VALUE = 3,
    READ_ONLY = 4,
    GEN_ERR = 5,
        
    // V2c Errors
    NO_ACCESS = 6,
    WRONG_TYPE = 7,
    WRONG_LENGTH = 8,
    WRONG_ENCODING = 9,
    WRONG_VALUE = 10,
    NO_CREATION = 11,
    INCONSISTENT_VALUE = 12,
    RESOURCE_UNAVAILABLE = 13,
    COMMIT_FAILED = 14,
    UNDO_FAILED = 15,
    AUTHORIZATION_ERROR = 16,
    NOT_WRITABLE = 17,
    INCONSISTENT_NAME = 18
} SNMP_ERROR_STATUS;

#define SNMP_V1_MAX_ERROR GEN_ERR

#define SNMP_ERROR_VERSION_CTRL(error, version) (((version) == SNMP_VERSION_1 && (error) > SNMP_V1_MAX_ERROR) ? SNMP_V1_MAX_ERROR : (error))

// Used for situations where in V2 an error exists but in V1 a less-specific error exists that isn't GEN_ERR
#define SNMP_ERROR_VERSION_CTRL_DEF(error, version, elseError) (((version) == SNMP_VERSION_1 && (error) > SNMP_V1_MAX_ERROR) ? SNMP_ERROR_VERSION_CTRL(elseError, version) : error)

/* RFC1213 OIDs — access modes per RFC 1213. All seven are registered ONLY when a
 * sketch (or the built-in sysUpTime, below) asks for them: no library pre-allocation.
 * The addRFC1213SystemGroup() helper owns the six configurable ones (see README). */
#define RFC1213_OID_sysDescr            (".1.3.6.1.2.1.1.1.0")   /* Read-only; helper param 1  */
#define RFC1213_OID_sysObjectID         (".1.3.6.1.2.1.1.2.0")
#define RFC1213_OID_sysUpTime           (".1.3.6.1.2.1.1.3.0")   /* Read-only; BUILT-IN dynamic (library-computed at request time) unless SNMP_NO_BUILTIN_SYSUPTIME is defined */
#define SNMPv2_SNMPTRAP_OID_0           (".1.3.6.1.6.3.1.1.4.1.0")   /* RFC 3416 §4.2.6/§4.2.7: mandatory varbind #2 NAME in SNMPv2c Trap/Inform.
                                                                         Value is the NOTIFICATION-TYPE OID supplied via SNMPTrap::setTrapOID() */
#define RFC1213_OID_sysContact          (".1.3.6.1.2.1.1.4.0")   /* Read-Write; helper param (needs buffer length) */
#define RFC1213_OID_sysName             (".1.3.6.1.2.1.1.5.0")   /* Read-Write; helper param (needs buffer length) */
#define RFC1213_OID_sysLocation         (".1.3.6.1.2.1.1.6.0")   /* Read-Write; helper param (needs buffer length) */
#define RFC1213_OID_sysServices         (".1.3.6.1.2.1.1.7.0")   /* Read-only; helper param (typical: 72 IP+TCP host, 64 L3 device, 0 endpoint) */

/* CONVENIENCE TYPE ONLY — the library never instantiates or pre-allocates this
 * struct; system OIDs exist only for the handlers a sketch registers (or the
 * built-in sysUpTime). sysObjectID is deliberately outside the helper: it is
 * the user's enterprise OID (add manually with addOIDHandler()). */
typedef struct RFC1213SystemStruct {
        char*           sysDescr;               /* .1.3.6.1.2.1.1.1.0   Read-only   */
        char*           sysObjectID;            /* .1.3.6.1.2.1.1.2.0   Read-only (enterprise OID, user-owned) */
        uint32_t        sysUpTime;              /* .1.3.6.1.2.1.1.3.0   Read-only (built-in dynamic by default) */
        char*           sysContact;             /* .1.3.6.1.2.1.1.4.0   Read-Write  */
        char*           sysName;                /* .1.3.6.1.2.1.1.5.0   Read-Write  */
        char*           sysLocation;            /* .1.3.6.1.2.1.1.6.0   Read-Write  */
        int32_t         sysServices;            /* .1.3.6.1.2.1.1.7.0   Read-only   */
    } RFC1213_list;

// DEBUG
#if defined(COMPILING_TESTS)
    #define _LOGD(...)          printf(__VA_ARGS__)
    #define _LOGI(...)          printf(__VA_ARGS__)
    #define _LOGW(...)          printf(__VA_ARGS__)
    #define _LOGE(...)          printf(__VA_ARGS__)
#elif defined(ESP32)
    #include <esp_log.h>
    
    #define _LOGD(...)          ESP_LOGD(SNMP_TAG, __VA_ARGS__)
    #define _LOGI(...)          ESP_LOGI(SNMP_TAG, __VA_ARGS__)
    #define _LOGW(...)          ESP_LOGW(SNMP_TAG, __VA_ARGS__)
    #define _LOGE(...)          ESP_LOGE(SNMP_TAG, __VA_ARGS__)
#else
    #define _LOGD(...)          printf(__VA_ARGS__)
    #define _LOGI(...)          printf(__VA_ARGS__)
    #define _LOGW(...)          printf(__VA_ARGS__)
    #define _LOGE(...)          printf(__VA_ARGS__)
#endif

// ----
#if (DEBUG ==1)
    #define SNMP_LOGD           _LOGD
    #define SNMP_LOGI           _LOGI
    #define SNMP_LOGW           _LOGW
    #define SNMP_LOGE           _LOGE
#elif (DEBUG ==2)
    #define SNMP_LOGD(...)
    #define SNMP_LOGI           _LOGI
    #define SNMP_LOGW           _LOGW
    #define SNMP_LOGE           _LOGE
#else
    #define SNMP_LOGD(...)
    #define SNMP_LOGI(...)
    #define SNMP_LOGW(...)
    #define SNMP_LOGE(...)
#endif

#endif
