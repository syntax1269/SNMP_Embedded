# SNMP_Embedded Technical Manual

## 1. Scope

SNMP_Embedded is an Arduino-compatible SNMP agent for resource-constrained devices. The public API supports SNMPv1 and SNMPv2c request/response traffic, including GET, GETNEXT, GETBULK, SET, traps, and informs.

The library is designed for long-running devices where predictable memory use matters more than allocating convenience objects during request processing. Register handlers during startup, keep their backing storage alive, and call `loop()` frequently.

This manual describes the public API and the configuration decisions that affect memory, packet behavior, and compatibility.

---

## 2. Minimal agent lifecycle

```cpp
#include <WiFiUdp.h>
#include <SNMP_Embedded.h>

WiFiUDP udp;
SNMPAgent snmp("public", "private");
int temperature = 23;

void setup() {
    // Initialize the network before starting the agent.
    snmp.setUDP(&udp);
    snmp.begin();

    snmp.addIntegerHandler(
        ".1.3.6.1.4.1.99999.1.0",
        &temperature);

    snmp.sortHandlers();
}

void loop() {
    snmp.loop();
}
```

### Startup rules

1. Construct the agent before `setup()` or at the beginning of `setup()`.
2. Initialize the network interface and provide its UDP object with `setUDP()`.
3. Call `begin()` once the UDP object is ready.
4. Register handlers during startup.
5. Call `sortHandlers()` after the final registration or after any handler removal.
6. Call `snmp.loop()` as often as possible. Do not put long blocking delays in the main loop.
7. Keep every variable, string buffer, byte array, callback, and trap object used by a handler alive for as long as the handler remains registered.

The agent owns its registered callback records and their OID storage. It does not own the application variables or buffers supplied to handlers.

---

## 3. Communities and protocol behavior

```cpp
SNMPAgent readWriteAgent("public", "private");
SNMPAgent readOnlyAgent("public");
SNMPAgent defaultAgent;
```

- The read-only community is used for GET, GETNEXT, and GETBULK.
- The read-write community is required for SET.
- A request with an invalid community is rejected without invoking an application handler.
- Responses use the same SNMP version as the request.
- SNMPv1 and SNMPv2c have different error and exception encodings; the library performs the appropriate response mapping for the request version.

Communities can also be changed after construction:

```cpp
snmp.setReadOnlyCommunity("monitor");
snmp.setReadWriteCommunity("control");
```

For deployments requiring stronger authentication or privacy, place the agent behind the application's authenticated transport boundary. SNMP_Embedded v3.4.4 does not implement SNMPv3 security processing.

---

## 4. Handler API

All handler methods return a `ValueCallback*`. Keep that pointer if the handler will later be used in a trap, inspected for `setOccurred`, or removed.

| Method | Backing value | Access |
|---|---|---|
| `addIntegerHandler()` | `int*` | read-only or SETtable |
| `addReadOnlyIntegerHandler()` | copied `int` | read-only |
| `addDynamicIntegerHandler()` | `int callback()` | read-only |
| `addReadWriteStringHandler()` | `char**` plus capacity | read-only or SETtable |
| `addReadOnlyStaticStringHandler()` | `const char*` | read-only |
| `addDynamicReadOnlyStringHandler()` | `const char* callback()` | read-only |
| `addOpaqueHandler()` | `uint8_t*` plus length | read-only or SETtable |
| `addTimestampHandler()` | `uint32_t*` | read-only or SETtable |
| `addDynamicReadOnlyTimestampHandler()` | `uint32_t callback()` | read-only |
| `addOIDHandler()` | dotted OID string | read-only |
| `addCounter32Handler()` | `uint32_t*` | read-only |
| `addCounter64Handler()` | `uint64_t*` | read-only |
| `addGaugeHandler()` | `uint32_t*` | read-only |

Example:

```cpp
int currentValue = 7;
uint32_t packetCount = 0;
uint64_t bytesTotal = 0;
uint8_t statusBytes[] = { 0x01, 0x02, 0x03 };

ValueCallback* valueHandler =
    snmp.addIntegerHandler(".1.3.6.1.4.1.99999.1.0", &currentValue);

snmp.addCounter32Handler(
    ".1.3.6.1.4.1.99999.2.0", &packetCount);

snmp.addCounter64Handler(
    ".1.3.6.1.4.1.99999.3.0", &bytesTotal);

snmp.addOpaqueHandler(
    ".1.3.6.1.4.1.99999.4.0", statusBytes,
    sizeof(statusBytes));
```

### SETtable values

```cpp
int threshold = 10;
ValueCallback* thresholdHandler = snmp.addIntegerHandler(
    ".1.3.6.1.4.1.99999.10.0",
    &threshold,
    true);
```

After `loop()` processes a successful SET, the callback's `setOccurred` field becomes true. Clear it after handling the application event:

```cpp
if (thresholdHandler->setOccurred) {
    thresholdHandler->resetSetOccurred();
    // Apply the new threshold to the device.
}
```

String handlers require fixed, writable storage for SET operations:

```cpp
char contactStorage[64];
char* contact = contactStorage;

snmp.addReadWriteStringHandler(
    ".1.3.6.1.2.1.1.4.0",
    &contact,
    sizeof(contactStorage),
    true);
```

The capacity is a hard boundary. An over-length SET is rejected rather than truncated into an invalid value.

### Handler management

```cpp
snmp.sortHandlers();
snmp.removeHandler(valueHandler);
snmp.sortHandlers();
snmp.printAllOIDsTo(Serial);
```

Sorting is required for correct GETNEXT and GETBULK traversal.

---

## 5. RFC 1213 system group

The library provides the standard RFC 1213 OID constants and a helper for the six configurable system objects. `sysUpTime` is separate: it is registered automatically as a live library-owned value unless `SNMP_NO_BUILTIN_SYSUPTIME` is enabled. `sysObjectID` remains application-owned because it identifies the enterprise-specific device.

### Recommended array-based form

```cpp
static const char sysDescr[] = "Environmental sensor";
static char sysContact[] = "operator@example.com";
static char sysName[] = "sensor-01";
static char sysLocation[] = "laboratory";
static int sysServices = 72;

snmp.addRFC1213SystemGroup(
    sysDescr,
    sysContact,
    sysName,
    sysLocation,
    &sysServices);
```

The three writable string capacities are deduced from the real arrays. No `sizeof()` argument is required.

To omit an object, use `RFC1213_SKIP`:

```cpp
snmp.addRFC1213SystemGroup(
    sysDescr,
    RFC1213_SKIP,  // no sysContact
    sysName,
    RFC1213_SKIP,  // no sysLocation
    &sysServices);
```

An omitted object is not registered. GET behavior follows the request version's normal no-such-object/no-such-name semantics, and traversal proceeds to the next available OID.

### Runtime-sized pointer form

When storage is not a compile-time array, use the pointer-and-length overload:

```cpp
char* contact = runtimeBuffer;
char* name = runtimeName;
char* location = runtimeLocation;

snmp.addRFC1213SystemGroup(
    sysDescr,
    &contact, contactCapacity,
    &name, nameCapacity,
    &location, locationCapacity,
    &sysServices);
```

A zero capacity does not register the corresponding writable object. The helper returns `RFC1213Config`, which contains the callback pointers and `registeredCount` for the objects actually added.

### `sysUpTime`

By default, the library calculates `sysUpTime` at request time. The same source is used for notification timestamps, so the reported uptime remains current without a sketch-maintained counter.

To provide an application-owned time source:

1. Build with `SNMP_NO_BUILTIN_SYSUPTIME`.
2. Register `.1.3.6.1.2.1.1.3.0` with `addTimestampHandler()` or a dynamic timestamp handler.
3. Keep that value current from the application's clock.

The library refuses a duplicate `sysUpTime` registration while its built-in handler is active.

---

## 6. Memory model and configuration flags

Request processing is bounded by fixed packet storage, fixed callback arrays, and the ASN placement pool. The default zero-copy path reads BER directly from the received packet and writes the response into the output buffer. Built-in packet processing performs no per-packet heap allocation.

The compile-time maximum engine footprint is exposed as:

```cpp
SNMP_ENGINE_MAX_RAM_BYTES
```

It accounts for the ASN pool arena, the packet buffer, and the worst-case VarBind array for the selected configuration.

### Important configuration flags

| Flag | Default | Effect |
|---|---:|---|
| `SNMP_ZERO_COPY` | `1` | Selects the in-place BER reader and direct response writer. Set to `0` for the owning compatibility path. |
| `SNMP_NO_BUILTIN_SYSUPTIME` | `0` | Removes the automatically registered uptime handler so the application can provide its own. |
| `SNMP_NO_TRAPS` | `0` | Compiles out traps, informs, and their retry machinery for request-only devices. |
| `SNMP_POOL_LOCK_AT_BOOT` | `1` | Claims the pool arena at startup before normal application activity. |
| `SNMP_POOLS_IN_BSS` | platform-dependent | Places the pool arena in static storage when enabled. |
| `SNMP_TRAP_VB_RESERVE` | `0` | Reserves pool capacity for trap varbinds. Increase it when notifications carry application varbinds. |
| `SNMP_MAX_VARBINDS` | derived | Sets the wire varbind cap; the default is derived from packet size. |
| `SNMP_MAX_CALLBACKS_PER_AGENT` | platform-dependent | Sets the callback table capacity and contributes to the pool formula. |
| `MAX_SNMP_PACKET_LENGTH` | platform-dependent | Sets the packet budget used by the parser, writer, and derived varbind cap. |

Size-affecting definitions must be supplied consistently to the library and the sketch. Do not define a class-layout value in only one source file.

The pool formula is:

```text
pool = max(2 * SNMP_MAX_VARBINDS,
           trap transient requirement)
       + SNMP_POOL_IDLE_MARGIN
       + SNMP_MAX_CALLBACKS_PER_AGENT
```

With `SNMP_NO_TRAPS=1`, the trap transient requirement is removed. The library rejects contradictory settings such as trap varbind reservation combined with traps disabled.

### Minimal-footprint guidance

- Register only the OIDs the device needs.
- Use the derived packet and callback caps rather than broad manual overrides.
- Use `SNMP_NO_TRAPS` for request-only devices.
- Use `SNMP_NO_BUILTIN_SYSUPTIME` only when the application already owns a reliable uptime source.
- Prefer static or startup-created trap objects; do not construct traps for every notification.
- Keep strings and opaque values in fixed application buffers.

---

## 7. Runtime statistics

`getRuntimeStats()` copies a no-allocation snapshot into an application-provided structure:

```cpp
SNMP_RuntimeStats stats;
snmp.getRuntimeStats(&stats);

Serial.printf(
    "rx=%u malformed=%u rejected=%u tooBig=%u "
    "allocFail=%u pool=%u/%u peak=%u\n",
    (unsigned)stats.packets_received,
    (unsigned)stats.malformed_packets,
    (unsigned)stats.packets_rejected,
    (unsigned)stats.too_big_responses,
    (unsigned)stats.allocation_failures,
    (unsigned)stats.pool_used,
    (unsigned)stats.pool_cap,
    (unsigned)stats.pool_high_water);
```

The fields are:

- `pool_used`: current ASN pool occupancy.
- `pool_high_water`: highest occupancy observed since boot.
- `pool_cap`: configured pool capacity.
- `packets_received`: datagrams accepted by the agent loop.
- `packets_rejected`: valid packets denied by community access.
- `malformed_packets`: packets rejected during parsing.
- `too_big_responses`: RFC 3416 `tooBig` responses sent.
- `allocation_failures`: failed pool allocations.
- `double_release_errors`: pool ownership violations detected by the allocator.

Pool fields are live values. Packet and error fields are monotonic counters since boot.

---

## 8. Traps and informs

Prefer a static trap object or construct one once during startup:

```cpp
static SNMPTrap notification("public", SNMP_VERSION_2C);

void setup() {
    notification.setUDP(&udp);
    notification.setTrapOID(
        new OIDType(".1.3.6.1.6.3.1.1.5.1"));
    notification.setSpecificTrap(1);
    notification.setIP(managerAddress);
}
```

A trap can include callback values:

```cpp
notification.addOIDPointer(valueHandler);
```

Send a notification with `sendTrapTo()`:

```cpp
snmp.sendTrapTo(
    &notification,
    managerAddress,
    true,   // replace queued request when appropriate
    2,      // retry count for an inform
    5000);  // retry timeout in milliseconds
```

For an SNMPv2c InformRequest, call `setInform(true)`. The manager acknowledges an inform with a Response PDU. The library matches that response by request ID and retries until the configured limit.

### Inform acknowledgment callback

```cpp
void informAcknowledged(unsigned long requestID, bool success) {
    Serial.printf("inform %lu: %s\n",
                  requestID,
                  success ? "accepted" : "rejected");
}

void setup() {
    snmp.setInformAckCallback(informAcknowledged);
}
```

The callback runs from `snmp.loop()`. It fires for a matched response and reports whether the response carried `noError`. A timed-out inform with no response does not produce an acknowledgment callback.

When `SNMP_NO_TRAPS=1` is enabled, the notification and inform API is intentionally unavailable.

---

## 9. Packet paths and compatibility

`SNMP_ZERO_COPY=1` is the default. It provides:

- in-place BER validation over the UDP receive buffer;
- raw encoded-OID matching without rendering dotted strings;
- direct response serialization into the packet buffer;
- measured response-size checks before transmission.

`SNMP_ZERO_COPY=0` keeps the owning container path available for compatibility and direct packet parsing. The public agent lifecycle and handler API remain the same.

The built-in callback classes use the pool-owning `AsnPtr` path. The deprecated `buildTypeWithValue()` virtual remains as a source-compatibility bridge for external subclasses. New custom callback implementations should override `buildTypeWithValueRaw()` and return a pool-owned value.

---

## 10. Response outcomes and troubleshooting

`SNMPAgent::loop()` returns an `SNMP_ERROR_RESPONSE` value. Common outcomes include:

| Result | Meaning |
|---|---|
| `SNMP_NO_PACKET` | No datagram was available. |
| `SNMP_GET_OCCURRED` | GET was processed. |
| `SNMP_GETNEXT_OCCURRED` | GETNEXT was processed. |
| `SNMP_GETBULK_OCCURRED` | GETBULK was processed. |
| `SNMP_SET_OCCURRED` | SET was processed. |
| `SNMP_ERROR_PACKET_SENT` | An error response, including `tooBig`, was sent. |
| `SNMP_REQUEST_INVALID` | The packet failed validation. |
| `SNMP_REQUEST_INVALID_COMMUNITY` | The community did not authorize the request. |
| `SNMP_REQUEST_TOO_LARGE` | The received datagram exceeded the packet budget. |
| `SNMP_FAILED_SERIALISATION` | A response could not be serialized into the configured budget. |

### Common configuration mistakes

- **GETNEXT appears empty:** call `sortHandlers()` after registration.
- **A writable system string is absent:** provide a real array or a non-zero pointer-form capacity.
- **A duplicate `sysUpTime` handler is rejected:** either use the built-in value or enable `SNMP_NO_BUILTIN_SYSUPTIME` before registering your own.
- **Pool exhaustion is reported:** reduce the number of simultaneous values or increase the globally consistent pool/capacity definitions.
- **Unexpected resets after changing sizes:** ensure every translation unit uses the same class-layout definitions.
- **A trap timestamp is stale:** use the built-in uptime or update the application-owned timestamp before sending.

---

## 11. Reference constants

The RFC 1213 constants are available from `defs.h`:

```cpp
RFC1213_OID_sysDescr
RFC1213_OID_sysObjectID
RFC1213_OID_sysUpTime
RFC1213_OID_sysContact
RFC1213_OID_sysName
RFC1213_OID_sysLocation
RFC1213_OID_sysServices
```

The public examples demonstrate Wi-Fi, Ethernet, system-group registration, custom OIDs, traps, informs, and minimal-footprint configurations.
