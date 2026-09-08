# SNMP_Embedded

**A memory-safe, deterministic-RAM SNMPv2c agent for Arduino — ESP32 & ESP8266 (proven on a 1 MB ESP8266).**

## Current Version: 3.4.1

> **Highlights:** **zero-copy packet path** (in-place BER parse + direct-to-buffer response build — no intermediate containers on the hot path), compile-time **derived resource sizing** with an **exact-pricing pool formula** (every pool slot priced by a named, code-verified consumer), **boot-time arena lock-in**, **stateless trap/inform sends**, **loud failure modes** (over-cap requests answer RFC 3416 `tooBig` instead of being silently dropped), and a **CI-validated test suite** (host Catch2 tests, ESP8266 + ESP32 example compile matrix). See [Version History](#version-history) below.

**All development on SNMP_Embedded happens in this repository.**

**Pull requests and issue reports are welcome.**

---

## Features
* Full SNMPv2c Data Type support:
  * INTEGER `int`
  * STRING  `char[]` / `const char*` (C-style strings, no `std::string` or Arduino `String`)
  * NULLTYPE
  * OIDTYPE `const char*` (dotted-decimal, e.g. ".1.3.6.1.4.1.5.0")
* Complex data type support:
  * NETWORK ADDRESS
  * COUNTER32 `uint32_t`
  * GAUGE32 `uint32_t`
  * TIMESTAMP `uint32_t`
  * OPAQUE `uint8_t*`
  * COUNTER64 `uint64_t`
* SNMP PDU Support
  * GetRequest
  * GetNextRequest
  * GetResponse (For SNMPv2c INFORM Responses only for now)
  * SetRequest
  * SNMPv2 Trap
  * GetBulkRequest
  * InformRequest
* Deterministic memory
  * Compile-time derived pool sizing — the arena scales with the handlers you register
  * Boot-time lock-in — one contiguous arena claimed before `setup()`/WiFi; zero per-packet heap traffic (proven: measured 0 heap allocations per packet on every request path since v3.4.2)
  * Loud failure modes — over-cap GetBulk answers an RFC 3416 `tooBig` error PDU instead of silently truncating
  * Hardware-validated: ESP8266 30-minute soak campaigns, 0 pool alarms / 0 reboots / flat heap

It was designed, improved and tested around an ESP8266, but will work with any Arduino-based device that has a UDP object available. Optimized for ESP8266 and other memory-constrained embedded targets — the library auto-tunes a reduced "TINY" profile on ESP8266 and was validated with 30+ minute soak and flood campaigns on a 1 MB ESP8266 board (flat heap, zero allocation failures, bounded deterministic RAM).

The example goes into detail around how to use, or look at `src/SNMP_Embedded.h` for the API.

## Memory Model

The ASN pool is **derived at compile time** from the flags your build already sets — there is no fixed pool size to hand-tune. Since v3.4.0 the formula is **exactly priced**: every slot is charged to a named, source-verified consumer, with nothing left unexplained:

```
pool = max( 2*SNMP_MAX_VARBINDS ,                       // request tick: zc Phase A holds
                                            //   VB decoded values + VB response values
            16 + 3*SNMP_TRAP_VB_RESERVE )   // trap tick: minimal v2c trap tree =
                                            //   4 envelope + 5 PDU header + 7 mandatory varbinds
  + 4                                       // SNMP_POOL_IDLE_MARGIN: explicit idle buffer
  + SNMP_MAX_CALLBACKS_PER_AGENT            // permanent: OID + value per registered handler
```

With `SNMP_NO_TRAPS=1` (v3.4.1) the whole trap tick is priced at zero — the pool becomes simply `2*SNMP_MAX_VARBINDS + 4 + SNMP_MAX_CALLBACKS_PER_AGENT` (e.g. 25 slots instead of 33 on the 13-handler 768-B profile). See the flags table below.

A single-threaded agent never overlaps a request tick with a trap rebuild, so the worst tick is the **larger** of the two, not their sum. Builds that never send traps or informs can set `SNMP_NO_TRAPS=1` (global build flag): the entire trap/inform subsystem — the `SNMPTrap` class, the inform retry queue, the inform-ack callback — is compiled out, any accidental trap call fails to compile with a message naming the flag, and the pool drops the 16-slot trap-tree term. The hardware-proven pool floor (≥ 24 slots) is deliberately not relaxed by this flag: it was earned by crash evidence on the request path, which traps-off does not touch. Informs hold **zero** pool slots while queued (stateless design: build → transmit → release; retries rebuild from scratch) — a queued inform costs one small heap record, not packet slots. A sketch that attaches varbinds to its traps sets `SNMP_TRAP_VB_RESERVE` to its maximum trap varbind count (+3 slots each); unreserved overflow fails loudly (pool-exhausted log, trap not sent) rather than silently.

On the default 13-handler ESP8266 profile this derives **33 slots** — the worst tick (29) plus the 4-slot margin. Measured on hardware: flood + SET + walk + inform-queue-saturated stress peaks at 27 (the 2-slot gap is the declared-vs-registered handler conservatism working as intended).

### The zero-copy packet path (v3.4.0)

Inbound packets are parsed **in place** over the UDP buffer: a flat TLV walk (`BerView`/`ber_peek`) validates structure and records slices — no per-varbind OID containers, no dotted-string renders. Handler dispatch matches the request's raw encoded-OID bytes against handler OIDs (`memcmp`) — the same bytes that define sort order, so walk semantics are exact. Responses are written **directly into the outgoing UDP buffer** (`BerWriter`): request OID slices are echoed verbatim, handler values are encoded once, and the response-size fit check is *measured*, not worst-case arithmetic — `tooBig` is answered only when genuinely true.

The owning container API (`SNMPPacket::parseFrom()`) is unchanged and remains the public contract for sketches that parse packets directly. `SNMP_ZERO_COPY=0` (global build flag) restores the classic container path unchanged as an escape hatch.

The arena is **locked in at boot**: every `SNMPAgent` constructor calls `ASNPool::lockInArena()`, which claims the one contiguous `sizeof(Slot) x SNMP_POOL_ASN_OBJECTS` block at global-constructor time — before `setup()`, before WiFi — while the heap is pristine. This replaces lazy first-parse allocation, which can fail on a fragmented heap and abort the sketch (ESP8266 runs with exceptions disabled). Lock-in is no-throw: on failure it logs a warning and falls back to the lazy path. `SNMP_POOL_LOCK_AT_BOOT=0` (global build flag) restores lazy allocation; `SNMP_POOLS_IN_BSS=1` places the arena in static BSS instead.

### Current profile defaults (tunable in [defs.h](src/include/defs.h))

| Constant | ESP8266 TINY (auto) | Default (ESP32 etc.) |
|---|---|---|
| `MAX_SNMP_PACKET_LENGTH` | 1024 | 1400 |
| `SNMP_MAX_OID_STR_LEN` | 192 | 256 |
| `SNMP_MAX_COMPLEX_CHILDREN` | 16 | 24 |
| `SNMP_MAX_VARBINDS` | 6 | 16 |
| `SNMP_MAX_CALLBACKS_PER_AGENT` | 24 | 64 |
| `SNMP_MAX_TRAPS_INFLIGHT` | 4 | 8 |
| `SNMP_MAX_CALLBACKS_PER_TRAP` | 8 | 16 |
| `SNMP_POOL_SLOT_SIZE` | 288 | 312 |
| `SNMP_POOL_ASN_OBJECTS` | derived (exact-pricing formula; e.g. 33 at 24 handlers) | derived (exact-pricing formula) |
| `SNMP_TRAP_VB_RESERVE` | 0 (raise if traps carry varbinds) | 0 |
| `SNMP_NO_TRAPS` | 0 (traps + informs enabled) | 0 |

Slot size is pinned to the measured largest BER container by exhaustive `static_assert`s — if a container grows, the build fails loudly instead of silently corrupting.

### !! Size overrides and the One-Definition Rule !!

Never `#define` size-affecting flags (`SNMP_MAX_CALLBACKS_PER_AGENT`, `SNMP_POOL_*`, `OCTET_TYPE_MAX_LENGTH`, `SNMP_MAX_OID_STR_LEN`, ...) **inside a sketch file**. They change class layout, so a sketch-only define makes the sketch and the compiled library disagree about object sizes → undefined behavior (on ESP8266, observed live: instant reboot loops). Set them as **global build flags** so every translation unit agrees:

```ini
; platformio.ini
build_flags = -DSNMP_MAX_CALLBACKS_PER_AGENT=64
```
```bash
# arduino-cli
arduino-cli compile --fqbn esp8266:esp8266:d1_mini \
  --build-flags "-DSNMP_MAX_CALLBACKS_PER_AGENT=64" MySketch
```

Behavior-only flags (e.g. `SNMP_POOL_LOCK_AT_BOOT`) do not change layout and are safe anywhere, but global flags remain the recommended style.

**Best practice on constrained targets:** after registering handlers in `setup()`, call `ASNPool::freezePermCount()` — it pins the exact permanent baseline so no slot is reserved pessimistically. (Without it, the auto-freeze safety net still guarantees correctness, but may freeze a slightly larger baseline if a startup trap allocated transients first.)

---

## Deterministic Memory (Zero-Heap Design)

Steady-state packet processing (`agent.loop()`, `sendTrapTo`, GET/GETNEXT/GETBULK/SET
decode + response build) performs **zero** `malloc`/`new`/`calloc`/`realloc`. All ASN.1 BER
objects come from the compile-time-sized placement pool; all VarBind/PDU/callback lists are
fixed C arrays with explicit compile-time capacity caps. Overflows return well-defined error
codes instead of undefined-behavior heap exhaustion. The library contains no `std::vector` /
`std::deque` / `std::list` anywhere in `src/` — a property enforced by the host test suite.

---

## Strings: C-Style Only

The library uses **fixed-size C-style strings** (`char[]` + `const char*` + explicit length fields) exclusively. The C++ `std::string` type and Arduino `String` class have been completely removed from all library code, examples, and callback APIs.

### Why this change
* **Zero heap fragmentation** — no dynamic `malloc`/`new` for string storage
* **Smaller binary** — eliminates `<string>` template instantiation bloat (~3–8 KB Flash on ESP8266)
* **Deterministic memory** — all buffers are compile-time sized, no surprise OOM at runtime
* **Faster** — no SBO/COW indirection; fixed `memcpy`/`strcmp` paths that the compiler can heavily optimize

### Buffer Sizing
Fixed maximum sizes are declared in [defs.h](src/include/defs.h):
| Constant                    | Value | Purpose                          |
|-----------------------------|-------|----------------------------------|
| `SNMP_MAX_COMMUNITY_LEN`    | 64    | Community string (RO/RW)         |
| `SNMP_MAX_OID_STR_LEN`      | 256   | OID dotted-decimal representation|
| `SNMP_MAX_STRING_LEN`       | 500   | OctetString (OID value payload)  |

These are conservative defaults; tune them in `defs.h` if you need smaller RAM footprint on the ESP8266.

### String Handlers

```cpp
// Read-only static string (preferred — no pointers, no buffers to manage)
char sysDescr[] = "ESP32 SNMP Agent";     // or const char* to a PROGMEM literal
snmp.addReadOnlyStaticStringHandler(".1.3.6.1.2.1.1.1.0", sysDescr);

// Read-write string: static buffer only (no malloc), pass the TRUE buffer size
char _sysContactBuf[255];
char* sysContact = _sysContactBuf;
snprintf(sysContact, sizeof(_sysContactBuf), "admin@example.com");
snmp.addReadWriteStringHandler(".1.3.6.1.2.1.1.4.0", &sysContact, sizeof(_sysContactBuf), true);

// Dynamic read-only callback
const char* getFirmwareVersion(void) { return LIBRARY_VERSION; }  // from defs.h
snmp.addReadOnlyStringHandler(".1.3.6.1.4.1.99.0", getFirmwareVersion);
```

---

It you need a STRING OID that can be written to/updated, be very sure that you need to update it, because you will be dealing with raw pointers into fixed-size buffers. Always pass the true buffer size as the `maxLength` parameter of `addReadWriteStringHandler` to prevent overflow. It's safer to use `addReadOnlyStaticStringHandler()` whenever possible.

This library does **not** support the Arduino `String` class and does **not** use the C++ `std::string` class — all string handling uses C `<cstring>` primitives (`strncpy`, `memcpy`, `strcmp`, `strlen`, `strchr`, `strtol`) with explicit bounds checking.

## Getting Started

To setup a simple SNMP Agent, include the required libraries and declare an instance of the `SNMPAgent` class;

```
#include <SNMP_Embedded.h>

/* Can declare read-write, or both read-only and read-write community strings */
SNMPAgent snmp("public", "private");
```

Depending on what arduino you are using, you will have to setup the wifi/internet conection for the device.
For ESP32, you can use `WiFi.begin()`, you will then need to supply a `UDP` object to the snmp library.

```
#include <WiFi.h>
#include <WiFiUdp.h>
WiFiUDP udp;

... later in setup()

WiFi.begin(ssid, password);

// Give snmp a pointer to the UDP object
snmp.setUDP(&udp);

// Add OID Handlers (see below)
...

snmp.begin();

... later in loop()
snmp.loop();
```

### Setting OID callbacks

If you want the Arduino to respond to an SNMP server at some specified OIDs, you need to implement a `ValueCallback` for each OID, attached to a variable to respond with.
Whenever an OID is requested by an SNMP manager, the ValueCallback for that OID is found, and the latest value of that variable is used to respond.

For example, to respones to the OID ".1.3.6.1.4.1.5.0" with the number: 5.
```
int testNumber = 5;
snmp.addIntegerHandler(".1.3.6.1.4.1.5.0", &testNumber);
```

You can enable SNMPSet requests, by setting `isSettable = true` as a parameter when adding the handler, for example:
```
int settableNumber = 0;
snmp.addIntegerHandler(".1.3.6.1.4.1.5.1", &settableNumber, true);
// snmpset -v 2c -c private <IP> 1.3.6.1.4.1.5.1 i 24
```

You can store the return value of the handler calls in a variable `ValueCallback*`, and use them later for things like SNMP Traps, or for removing the handler later.

Be sure to call `snmp.sortHandlers()` after adding any OID handlers, to ensure functions like SNMP Walk work correctly.


The full list of ValueCallback handlers you can specify can be found in `SNMP_Embedded.h`

### The RFC1213 System Group

The RFC1213 `system` group (`.1.3.6.1.2.1.1`) is the standard "who am I"
subtree every SNMP manager probes first: description, uptime, contact,
name, location, services.

SNMP_Embedded ships the OID constants for all seven system objects, and —
by default — registers **sysUpTime** (`.1.3.6.1.2.1.1.3.0`) for you as a
live, always-current value computed at request time. You never maintain
uptime yourself, and trap timestamps are automatically correct.

Everything else in the group is yours to choose. Register any subset with
one call:

```
// v3.3.5 auto-size form: pass the BUFFER ARRAYS — the library deduces each
// capacity, so SETs can never overflow and there is no sizeof() to type.
char sysContactBuf[64], sysNameBuf[64], sysLocBuf[64];
int sysServices = 72;  /* int (not int32_t): on ESP32 int32_t is 'long' and won't match */
snmp.addRFC1213SystemGroup(sysDescr,
    sysContactBuf,            // read-write, capacity deduced from the array
    sysNameBuf,               // read-write, capacity deduced
    sysLocBuf,                // read-write, capacity deduced
    &sysServices);            // read-only integer

// skip any OID with RFC1213_SKIP in its slot — here only sysName + sysLocation exist:
snmp.addRFC1213SystemGroup(sysDescr,
    RFC1213_SKIP,             // sysContact — not served by this agent
    sysNameBuf,
    sysLocBuf,
    nullptr);                 // sysServices — not served
```

Notes:

- The auto-size buffers must be real arrays (`char buf[64]`); a bare `char*`
  has no deducible capacity and fails to compile rather than guessing. For
  heap or runtime-sized storage, the advanced pointer form remains:
  `snmp.addRFC1213SystemGroup(sysDescr, &ptr, sizeof(buf), ...)`.
- Each registered OID costs exactly one pool slot plus its string buffer.
  OIDs you skip cost nothing. GETs on skipped OIDs return the standard
  no-such-object response; walks bridge the gaps cleanly.
- Read-write strings can never overflow: the deduced (or supplied) buffer
  length bounds every SET.
- `sysObjectID` is deliberately not covered by the helper: it is your
  enterprise OID. Add it manually when you want it:
  `snmp.addOIDHandler(RFC1213_OID_sysObjectID, "1.3.6.1.4.1.99999");`
- Recommended `sysServices` values: 72 for an IP host with TCP, 64 for a
  network-layer device, 0 for a pure endpoint.
- A build that never calls the helper registers nothing in the system
  group beyond the built-in uptime.
- The helper returns an `RFC1213Config` record (`registeredCount` plus one
  `ValueCallback*` per configured OID) so sketches can verify exactly what
  was registered.

### Minimal-footprint builds

Two compile-time flags shrink the agent for endpoints that do not need the
full feature set. Both are **global build flags** (see the One-Definition
Rule above) and apply to every MCU and platform the library builds for:

- `SNMP_NO_BUILTIN_SYSUPTIME` — removes the built-in uptime registration
  (one pool slot reclaimed). With the flag, sysUpTime becomes a normal OID
  you may register yourself — either dynamically or bound to your own
  variable that you keep fresh.

- `SNMP_NO_TRAPS` (v3.4.1) — **compile-time removal of the entire trap and
  inform subsystem** for builds that only ever answer requests. The
  `SNMPTrap` class, the inform retry queue, and the inform-ack callback do
  not exist in the binary, and the pool formula drops the 16-slot trap-tree
  term (`pool = 2*SNMP_MAX_VARBINDS + 4 + SNMP_MAX_CALLBACKS_PER_AGENT`;
  the 13-handler 768-B profile derives 25 slots instead of 33). Any
  accidental trap call fails to compile with a message naming the flag and
  the remedy, and combining it with `SNMP_TRAP_VB_RESERVE > 0` is a build
  error. The flag is permanent API surface: default-off builds are
  bit-identical to previous releases.

### SNMP Traps

You can send SNMP v1 traps, as well as SNMPv2 Trap and INFORMS with this library.

There are a few requirements in setting up a trap in order to comply with the SNMP RFC.

```
// Setup a trap object for later use, specify the SNMP version to use
// SNMP_VERSION_1 or SNMP_VERSION_2C

// PREFERRED on embedded targets: construct it STATICALLY (global or `static`).
// The constructor itself never allocates, so a static trap object costs only
// its sizeof() in static RAM and keeps the runtime steady state entirely free
// of dynamic allocations — the main agent loop is already allocation-free by
// design, and a static trap preserves that guarantee for the trap path too.
static SNMPTrap testTrap("public", SNMP_VERSION_2C);

// Pointer style is still supported (e.g. when the trap's lifetime must be
// managed manually), but on low-memory targets prefer the static form above:
// SNMPTrap* testTrap = new SNMPTrap("public", SNMP_VERSION_2C);   // heap
//   — create it once during startup (never per-send) if you use this form.
```

**Uptime timestamp:** SNMP traps must carry a sysUpTime value. Since
v3.3.4 the library supplies this automatically from its built-in live
uptime — no counter variable and no callback needed. If you want a
sketch-owned timestamp instead (e.g. an external wall-clock source), set
one explicitly and it takes precedence:

```
TimestampCallback* timestampCallback;
int tensOfMillisCounter = 0;
```
In `setup()` (only needed when overriding the built-in uptime):
```
// Optional: sketch-owned uptime source for the trap timestamp
timestampCallback = (TimestampCallback*)snmp.addTimestampHandler(".1.3.6.1.2.1.1.3.0", &tensOfMillisCounter);

// Set UDP Object for trap to be sent on
testTrap.setUDP(&udp);

// OID of the trap — pass the C-style string; the library heap-allocates the
// OID ONCE here and owns/frees it across sends (never allocate it per send):
testTrap.setTrapOID(".1.3.6.1.2.1.33.2");

// Specific Number of the trap
testTrap.setSpecificTrap(1);

// Set the uptime counter to use in the trap (optional since v3.3.4 —
// omit it and the library's built-in live uptime is used automatically)
testTrap.setUptimeCallback(timestampCallback);

// Set some previously set OID Callbacks to send these values with the trap (optional)
testTrap.addOIDPointer(previouslySetValueCallback);

// Set our Source IP so the receiver knows where this is coming from
testTrap.setIP(WiFi.localIP());

// Set INFORM to be true or false (only works for SNMPV2 traps)
testTrap.setInform(true);
```

in `loop()`

```
// must be called as often as possible
snmp.loop();

// Update our timestamp value
tensOfMillisCounter = millis()/10;

// Send the trap to the specified IP address

IPAddress destinationIP = IPAddress(192, 168, 1, 243);

if(snmp.sendTrapTo(&testTrap, destinationIP, true, 2, 5000) != INVALID_SNMP_REQUEST_ID){
    Serial.println("Sent SNMP Trap");
} else {
    Serial.println("Couldn't send SNMP Trap");
}
```

The `snmp.sendTrapTo()` values of `true, 2, 5000` indicate that if this is an INFORM request, it will try to send the INFORM up to 2 times, with a Timeout of 5000 milliseconds before it gives up, if it receives no response from the other end. The snmp.loop() will keep trying to resend the trap until the timeout or retry limit is reached.

Inform delivery **is** tracked: per RFC 3416, the receiving manager answers an
InformRequest with a Response PDU, and the library matches that response (by
request ID) inside `snmp.loop()` — dequeuing the pending inform on success and
resending up to the configured retries on timeout (`sendTrapTo()`'s retry and
timeout arguments).

Since **v3.3.6** the acknowledgment is also available to your sketch — install
a callback and it fires once per matched Response PDU, from inside
`snmp.loop()` (never an ISR), with the inform's request ID and the responder's
outcome (`true` = the manager processed it with `noError`; `false` = it
responded with an error — rejected, not lost). The callback only fires for
request IDs that actually have a pending inform, so unsolicited Response PDUs
never produce phantom confirmations. Pass `nullptr` to uninstall:

```
void onInformAck(unsigned long requestID, bool success) {
    Serial.printf("Inform %lu: %s\r\n", requestID,
                  success ? "ACKED by manager" : "REJECTED (error response)");
}

// in setup(), before sending:
snmp.setInformAckCallback(onInformAck);
```

Informs that exhaust their retries with no response do **not** fire the ack
callback (no answer ever arrived); the queue item is simply retired and the
inform stops being resent.

---

## Measured Performance (v3.4.1 harness)

Every number below is a row in the internal measurement history (standardized
build → flash → soak → CSV runner); nothing is estimated. Reference platform:
ESP8266 ESP-01, 80 MHz, 768-B packet budget, 13 handlers, unpaced flood load
(1- and 5-minute soaks).

| Metric | Measured |
|---|---|
| Sustained throughput, unpaced flood | **~8.0 ops/s** (2,406–2,428 ops in 5 min) |
| Per-op latency medians (end-to-end) | GET sysDescr ~67–70 ms · SET ~73–76 ms · GETNEXT ~68–77 ms · 4-varbind bulkwalk ~188–193 ms · 6-wide bulkwalk ~129–140 ms |
| Pool under flood | 27 of 33 slots — the derived formula holds at max input rate |
| Heap floor during flood | ~32.5 KB free (frag ≤ 3 %) |
| Stability record | 0 pool alarms · 0 crashes · 0 reboots across every flood run |

Two honesty notes that the harness proved rather than assumed:

- **Throughput is network-and-host bound, not firmware bound.** Doubling the
  MCU clock (80 → 160 MHz) moved end-to-end throughput by less than 1.5 %,
  and swapping the vendor SDK (2.2.1+100 → 3.0.5) moved it by less than 3 %.
  The agent's share of each operation is a few milliseconds; the rest is the
  test host's CLI and the UDP round trip.
- **Flood failures are transport losses, not agent failures.** Across every
  flood run, the only failed operations were single datagrams lost by the
  Wi-Fi layer before they reached the agent (≈0.04 % of packets) — the
  firmware's 15-second diagnostics cadence never wavered and counters stayed
  consistent in every case.

## Version History

- **v3.4.2** — **True zero-heap packet path**: the `std::shared_ptr` wrappers
  that silently cost a heap control block per construction (~9–11 per packet on
  the zero-copy path, ~10× that on the classic path) are replaced by the
  move-only, pool-owning `AsnPtr<T>`. Measured with a per-packet allocation
  census: **0 heap allocations per GET/SET/GETNEXT/GETBULK on both paths**
  (was 11/9/9/2 zero-copy, 94/87/94/42 classic). New protected virtual
  `buildTypeWithValueRaw()` returns the pool-owned value directly; the old
  `buildTypeWithValue()` remains as a deprecated bridge for external
  subclasses (one control block per GET — migrate when convenient). No sketch
  changes required. See the [CHANGELOG](CHANGELOG.md).

- **v3.4.1** — **`SNMP_NO_TRAPS`**: compile-time removal of the whole trap/inform
  subsystem for request-only endpoints (loud compile errors on accidental trap
  use; pool drops the 16-slot trap-tree term — 25 slots instead of 33 on the
  13-handler 768-B profile). Flag off (default) is bit-identical to v3.4.0.
  Also fixes a latent tests-Makefile object-dir collision between local
  back-to-back profile builds. See the [CHANGELOG](CHANGELOG.md).
- **v3.4.0** — **Zero-copy packet path**: in-place BER parse over the UDP buffer,
  raw-byte OID dispatch, direct-to-buffer response writing with a measured fit
  check. **Exact-pricing pool formula** — every slot charged to a named consumer;
  pool −42/−58% by profile, free heap **+7.1 KB / +13.6 KB**, throughput +24–28%,
  byte-verified wire-identical. New `SNMP_TRAP_VB_RESERVE` flag; `SNMP_ZERO_COPY=0`
  escape hatch. No API changes. See the [CHANGELOG](CHANGELOG.md) for the full
  measured table.
- **v3.3.5** — Auto-size `addRFC1213SystemGroup()`: pass the buffer **arrays**
  directly (five arguments, no `sizeof()`); capacity is deduced from the array
  type, and a bare `char*` (unknown capacity) fails to compile. `RFC1213_SKIP`
  marks a skipped OID in one self-documenting token. Over-long SETs still
  answer `WRONG_LENGTH`; the v3.3.4 pointer+len form remains for heap- or
  runtime-sized storage.
- **v3.3.4** — One-call `addRFC1213SystemGroup()` helper (per-OID opt-out via
  `nullptr`) plus a built-in, library-owned dynamic **sysUpTime** computed at
  request time (opt out with `SNMP_NO_BUILTIN_SYSUPTIME`; feed your own clock
  with `SNMPAgent::setUptimeSource()`). Trap timestamps resolve through the
  same source, so GET uptime and trap sysUpTime can never disagree.
- **v3.3.3** — Initial baseline release of SNMP_Embedded. See the repository's
  commit history and [CHANGELOG.md](CHANGELOG.md) for the full line from the
  2021 upstream original through the memory-safety campaign.

---

## Origin & Attribution

SNMP_Embedded began as a fork of **Arduino_SNMP v2.1.0** by Aidan Cyr
([0neblock/Arduino_SNMP](https://github.com/0neblock/Arduino_SNMP), last upstream release ~2022).

Before being relaunched under its own name, the engine went through a hardware-validated
reliability campaign — pool memory-safety, derived sizing, boot-time lock-in, and
soak/flood testing on real ESP8266 hardware. The majority of the engine (~80% by measure)
now differs from the 2021 original: the BER pool allocator, sizing model, trap/inform
lifecycle, and the entire verification infrastructure are new, while the wire protocol
work and the original architecture that made those improvements possible are inherited.
