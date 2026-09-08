# SNMP_Embedded

## Reliable SNMP for long-running embedded devices

**SNMP_Embedded is an evolution of the familiar Arduino SNMP programming model, redesigned around deterministic memory management and long-running embedded reliability.**

The API remains simple and familiar, while packet processing uses bounded memory, zero-copy parsing, and zero dynamic allocation. This makes SNMP traffic itself incapable of causing progressive heap fragmentation over the lifetime of the device.

### Why it matters

- **Predictable resource use:** the ASN.1 pool is derived at compile time and claimed at startup.
- **Stable operation:** packet processing uses fixed buffers and pool ownership rather than per-packet heap bookkeeping.
- **Efficient on small devices:** BER data is read in place and responses are written directly to the packet buffer.
- **Simple integration:** register OIDs against ordinary C/C++ variables, then call `snmp.loop()`.
- **Protocol-aware failure handling:** oversized requests receive an explicit `tooBig` response instead of silently disappearing.
- **Long-running confidence:** the current release has survived sustained flood, malformed-input, and multi-hour hardware campaigns on ESP8266.

## Current version: 3.4.4

SNMP_Embedded supports SNMPv1 and SNMPv2c request/response traffic, including GET, GETNEXT, GETBULK, SET, traps, and informs. It also provides a live RFC 1213 `sysUpTime`, a one-call system-group helper, compile-time memory sizing, and runtime resource statistics.

> **Compatibility note:** SNMPv3 security processing is not included in v3.4.4. The public protocol surface is SNMPv1 and SNMPv2c.

---

## Quick start

```cpp
#include <WiFiUdp.h>
#include <SNMP_Embedded.h>

WiFiUDP udp;
SNMPAgent snmp("public", "private");
int sensorValue = 42;

void setup() {
    // Initialize the network before starting the agent.
    snmp.setUDP(&udp);
    snmp.begin();

    snmp.addIntegerHandler(
        ".1.3.6.1.4.1.99999.1.0",
        &sensorValue);
    snmp.sortHandlers();
}

void loop() {
    snmp.loop();
}
```

Register handlers during startup, keep their backing storage alive for the lifetime of the agent, and call `sortHandlers()` after adding or removing OIDs.

For the complete API, configuration flags, memory model, system group, traps, informs, runtime statistics, and troubleshooting, see the [SNMP_Embedded Technical Manual](SNMP_Embedded_Technical_Manual.md).

---

## Installation

- **Arduino Library Manager:** search for `SNMP_Embedded` and install the current release.
- **Manual installation:** download the repository archive and use the IDE's library installation command.
- **Build-system dependency:** add the repository to the dependency configuration used by your project and pin a release tag when reproducible builds are important:

```text
https://github.com/syntax1269/SNMP_Embedded.git@v3.4.4
```

Pinning a tag keeps a device build reproducible. Use a deliberately selected newer tag when upgrading.

---

## Features

- SNMPv1 and SNMPv2c request/response processing.
- GET, GETNEXT, GETBULK, SET, SNMPv1 traps, SNMPv2c traps, and informs.
- INTEGER, STRING, NULL, OID, COUNTER32, COUNTER64, GAUGE32, TIMESTAMP, OPAQUE, and network-address values.
- RFC 1213 system-group helper with per-object opt-out.
- Built-in dynamic `sysUpTime`, also used for notification timestamps.
- Zero-copy BER parsing and direct response serialization by default.
- Fixed-size C-style storage and compile-time capacity limits.
- Derived ASN pool sizing and boot-time arena lock-in.
- `SNMP_ENGINE_MAX_RAM_BYTES` compile-time maximum engine footprint.
- `SNMP_RuntimeStats` pool and packet counters.
- `SNMP_NO_TRAPS` and `SNMP_NO_BUILTIN_SYSUPTIME` footprint controls.
- Arduino Ethernet, ESP8266, and ESP32 examples.

The library is optimized for ESP8266 and other memory-constrained Arduino-compatible devices, while retaining a portable UDP-based integration model.

---

## RFC 1213 system group

The library supplies the standard system OID constants. `sysUpTime` is live by default; the other configurable objects are registered only when the sketch provides them.

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

The helper deduces the capacity of real writable character arrays. There is no `sizeof()` argument to maintain.

Skip any configurable object with `RFC1213_SKIP`:

```cpp
snmp.addRFC1213SystemGroup(
    sysDescr,
    RFC1213_SKIP,  // omit sysContact
    sysName,
    RFC1213_SKIP,  // omit sysLocation
    &sysServices);
```

Skipped OIDs are not allocated or served. `sysObjectID` remains application-owned because it identifies the enterprise-specific device.

To own uptime yourself, define `SNMP_NO_BUILTIN_SYSUPTIME` globally and register `.1.3.6.1.2.1.1.3.0` with an application-maintained timestamp handler. Without that flag, a duplicate uptime registration is refused so the live built-in value cannot be shadowed accidentally.

---

## Deterministic memory

The default packet path uses an in-place BER reader, raw encoded-OID matching, and a direct response writer. Built-in request processing performs no per-packet dynamic allocation. The owning packet API remains available as a compatibility path with `SNMP_ZERO_COPY=0`.

The pool is derived from the packet and handler limits. The engine's compile-time maximum is exposed as:

```cpp
SNMP_ENGINE_MAX_RAM_BYTES
```

The value accounts for the ASN pool arena, the UDP packet buffer, and the worst-case VarBind array for the selected configuration.

### Important build flags

| Flag | Default | Purpose |
|---|---:|---|
| `SNMP_ZERO_COPY` | `1` | Select the in-place packet path; `0` keeps the owning compatibility path. |
| `SNMP_NO_BUILTIN_SYSUPTIME` | `0` | Let the application provide its own uptime handler. |
| `SNMP_NO_TRAPS` | `0` | Remove traps, informs, and retry machinery from request-only builds. |
| `SNMP_POOL_LOCK_AT_BOOT` | `1` | Claim the pool arena at startup. |
| `SNMP_TRAP_VB_RESERVE` | `0` | Reserve capacity for trap varbinds. |
| `SNMP_MAX_VARBINDS` | derived | Set the maximum request/response varbind count. |
| `SNMP_MAX_CALLBACKS_PER_AGENT` | platform-dependent | Set callback table capacity. |
| `MAX_SNMP_PACKET_LENGTH` | platform-dependent | Set the packet budget. |

Size-affecting definitions must be supplied consistently to the library and the sketch. Configure them globally rather than in only one source file.

Use `SNMP_NO_TRAPS=1` for a request-only device. Use `SNMP_NO_BUILTIN_SYSUPTIME=1` only when the application already owns a reliable uptime source. The detailed pool formula and sizing guidance are in the technical manual.

---

## Runtime statistics

```cpp
SNMP_RuntimeStats stats;
snmp.getRuntimeStats(&stats);

Serial.printf(
    "rx=%u malformed=%u rejected=%u tooBig=%u pool=%u/%u peak=%u\n",
    (unsigned)stats.packets_received,
    (unsigned)stats.malformed_packets,
    (unsigned)stats.packets_rejected,
    (unsigned)stats.too_big_responses,
    (unsigned)stats.pool_used,
    (unsigned)stats.pool_cap,
    (unsigned)stats.pool_high_water);
```

Pool occupancy is live. Packet and error counters are monotonic since boot. The fields include packets received, malformed packets, community rejections, `tooBig` responses, allocation failures, and double-release alarms.

---

## Traps and informs

Prefer a static trap object or construct one during startup rather than creating notification objects during normal operation:

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

An SNMPv2c inform receives a Response PDU from the manager. The library matches that response by request ID and retries until the configured limit. Sketches can receive the result:

```cpp
void informAcknowledged(unsigned long requestID, bool success) {
    Serial.printf("inform %lu: %s\n", requestID,
                  success ? "accepted" : "rejected");
}

void setup() {
    snmp.setInformAckCallback(informAcknowledged);
}
```

The callback runs from `snmp.loop()` and fires for a matched response. A timed-out inform with no response does not produce an acknowledgment callback.

---

## Measured hardware results

The v3.4.4 release was verified on an ESP8266 ESP-01 using the 768-byte packet profile:

| Measurement | Result |
|---|---:|
| One-minute flood soak | 181 operations, 0 failures |
| Five-minute flood soak | 928 operations, 0 failures |
| Pool high-water | 27 / 33 slots |
| Parser-hardness campaign | 16,387 hostile datagrams |
| Liveness probes answered | 615 / 615 |
| Alarms, crashes, reboots | 0 / 0 / 0 |

The results demonstrate stable resource behavior under the tested conditions. Network throughput is affected by the radio, transport, and measurement endpoint, so these figures are reference measurements rather than universal performance guarantees.

---

## Examples

- `examples/ESP32_SNMP` — Wi-Fi agent with custom values and notifications.
- `examples/SNMP_Sensor` — larger sensor and management-information example.
- `examples/UNO_Ethernet_Minimal` — Arduino UNO and W5100 starting point.
- `examples/UNO_Ethernet_System` — Arduino UNO system-group example.
- `extras/demos` — additional Wi-Fi and Ethernet integration examples.

---

## Version history

- **v3.4.4** — runtime/high-water statistics, compile-time maximum engine footprint, parser hardening, and the zero-heap packet path brought together in the current release.
- **v3.4.3** — strict malformed-input handling for BER lengths and hostile version fields.
- **v3.4.2** — pool-owning packet values remove per-packet heap control-block activity from the built-in request paths.
- **v3.4.1** — public `SNMP_NO_TRAPS` build flag for request-only devices.
- **v3.4.0** — zero-copy BER parsing, direct response serialization, and derived pool sizing.
- **v3.3.3** — initial SNMP_Embedded baseline release.

See [CHANGELOG.md](CHANGELOG.md) for the detailed release history.

---

## Origin and attribution

SNMP_Embedded began as a fork of **Arduino_SNMP v2.1.0** by Aidan Cyr ([0neblock/Arduino_SNMP](https://github.com/0neblock/Arduino_SNMP)). The current project has substantially evolved the memory model, packet processing, notification lifecycle, configuration system, and verification coverage while retaining the original protocol foundation and attribution.
