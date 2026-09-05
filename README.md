# SNMP_Embedded

**A memory-safe, deterministic-RAM SNMPv2c agent for Arduino — ESP32 & ESP8266 (proven on a 1 MB ESP8266).**

## Current Version: 3.3.4

> **Highlights:** compile-time **derived resource sizing** (packet budget → varbind cap → pool size; no magic numbers), **boot-time arena lock-in** (memory claimed before `setup()`/WiFi — immune to heap fragmentation), **stateless trap/inform sends** (no pool-backed state survives a transmit), **loud failure modes** (over-cap requests answer RFC 3416 `tooBig` instead of being silently dropped), and a **CI-validated test suite** (arduino-lint, host Catch2 tests, ESP8266 + ESP32 example compile matrix). See [Version History](#version-history) below.

## Origin & Attribution

SNMP_Embedded began as a fork of **Arduino_SNMP v2.1.0** by Aidan Cyr
([0neblock/Arduino_SNMP](https://github.com/0neblock/Arduino_SNMP), last upstream release ~2022).

Before being relaunched under its own name, the engine went through a hardware-validated
reliability campaign — pool memory-safety, derived sizing, boot-time lock-in, and
soak/flood testing on real ESP8266 hardware. The majority of the engine (~80% by measure)
now differs from the 2021 original: the BER pool allocator, sizing model, trap/inform
lifecycle, and the entire verification infrastructure are new, while the wire protocol
work and the original architecture that made those improvements possible are inherited.

**All development on SNMP_Embedded happens in this repository.**

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
  * Boot-time lock-in — one contiguous arena claimed before `setup()`/WiFi; zero per-packet heap traffic
  * Loud failure modes — over-cap GetBulk answers an RFC 3416 `tooBig` error PDU instead of silently truncating
  * Hardware-validated: ESP8266 30-minute soak campaigns, 0 pool alarms / 0 reboots / flat heap

It was designed and tested around an ESP32, but will work with any Arduino-based device that has a UDP object available. Optimized for ESP8266 and other memory-constrained embedded targets — the library auto-tunes a reduced "TINY" profile on ESP8266 and was validated with 30+ minute soak and flood campaigns on a 1 MB ESP8266 board (flat heap, zero allocation failures, bounded deterministic RAM).

The example goes into detail around how to use, or look at `src/SNMP_Embedded.h` for the API.

## Memory Model

The ASN pool is **derived at compile time** from the flags your build already sets — there is no fixed pool size to hand-tune:

```
pool = SNMP_WORST_TICK_TRANSIENTS + SNMP_MAX_CALLBACKS_PER_AGENT

SNMP_WORST_TICK_TRANSIENTS
    = (SNMP_MAX_VARBINDS + 2) * 3        // GetBulk response at the varbind cap
    + (SNMP_MAX_TRAPS_INFLIGHT) * 3      // inflight informs decoded while a response builds
    + 24                                 // measured parse/response headroom
```

A sketch registering 12 handlers derives a smaller arena than one registering 40; a 40-handler deployment gets the pool the old fixed arena would have starved. The headroom term is measured, not guessed: 60 s of sustained Cr6-walk + SET + trap saturation on an ESP8266 peaked at 66 slots at TINY caps.

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
| `SNMP_POOL_ASN_OBJECTS` | derived (84 at TINY defaults) | derived (96 at default caps) |

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
// all six configurable OIDs
char sysContactBuf[64], sysNameBuf[64], sysLocBuf[64];
char* sysContact = sysContactBuf; char* sysName = sysNameBuf; char* sysLoc = sysLocBuf;
int sysServices = 72;  /* int (not int32_t): on ESP32 int32_t is 'long' and won't match */
snmp.addRFC1213SystemGroup(sysDescr,
    &sysContact, sizeof(sysContactBuf),
    &sysName,    sizeof(sysNameBuf),
    &sysLoc,     sizeof(sysLocBuf),
    &sysServices);

// just three — unlisted OIDs are simply not registered
snmp.addRFC1213SystemGroup(sysDescr,
    nullptr, 0,
    &sysName, sizeof(sysNameBuf),
    &sysLoc,  sizeof(sysLocBuf));
```

Notes:

- Each registered OID costs exactly one pool slot plus its string buffer.
  OIDs you skip cost nothing. GETs on skipped OIDs return the standard
  no-such-object response; walks bridge the gaps cleanly.
- Read-write strings REQUIRE the buffer length (`sizeof(buf)`) so SET
  requests can never overflow your storage.
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

Define `SNMP_NO_BUILTIN_SYSUPTIME` as a global build flag to remove the
built-in uptime registration (one pool slot reclaimed). With the flag,
sysUpTime becomes a normal OID you may register yourself — either
dynamically or bound to your own variable that you keep fresh.

### SNMP Traps

You can send SNMP v1 traps, as well as SNMPv2 Trap and INFORMS with this library.

There are a few requirements in setting up a trap in order to comply with the SNMP RFC.

```
// Setup a trap object for later use, specify the SNMP version to use 
// SNMP_VERSION_1 or SNMP_VERSION_2C

SNMPTrap* testTrap = new SNMPTrap("public", SNMP_VERSION_2C);
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
testTrap->setUDP(&udp);

// OID of the trap (C-style string)
testTrap->setTrapOID(new OIDType(".1.3.6.1.2.1.33.2"));

// Specific Number of the trap
testTrap->setSpecificTrap(1);

// Set the uptime counter to use in the trap (optional since v3.3.4 —
// omit it and the library's built-in live uptime is used automatically)
testTrap->setUptimeCallback(timestampCallback);

// Set some previously set OID Callbacks to send these values with the trap (optional)
testTrap->addOIDPointer(previouslySetValueCallback);

// Set our Source IP so the receiver knows where this is coming from
testTrap->setIP(WiFi.localIP());

// Set INFORM to be true or false (only works for SNMPV2 traps)
testTrap->setInform(true);
```

in `loop()`

```
// must be called as often as possible
snmp.loop();

// Update our timestamp value
tensOfMillisCounter = millis()/10;

// Send the trap to the specified IP address

IPAddress destinationIP = IPAddress(192, 168, 1, 243);

if(snmp.sendTrapTo(testTrap, destinationIP, true, 2, 5000) != INVALID_SNMP_REQUEST_ID){
    Serial.println("Sent SNMP Trap");
} else {
    Serial.println("Couldn't send SNMP Trap");
}
```

The `snmp.sendTrapTo()` values of `true, 2, 5000` indicate that if this is an INFORM request, it will try to send the INFORM up to 2 times, with a Timeout of 5000 milliseconds before it gives up, if it receives no response from the other end. The snmp.loop() will keep trying to resend the trap until the timeout or retry limit is reached.

There is currently no mechanism to know (with code) if an SNMP INFORM request has been responded to. 

---

## Version History

v3.3.3 is the initial baseline release of SNMP_Embedded. See the repository's commit
history for changes since this baseline.

Pull requests and issue reports are welcome.