# Changelog — SNMP_Embedded

## v3.3.4 — RFC1213 system group: one-call helper + built-in dynamic sysUpTime

**Additive feature release. No breaking API changes. One documented behavioural delta (below).**

### Added

- **`addRFC1213SystemGroup()`** — one-call registration of any subset of the six
  configurable RFC1213 system OIDs (sysDescr, sysContact, sysName, sysLocation,
  sysServices — sysObjectID deliberately excluded: it is the user's enterprise
  OID). Unlisted OIDs are never registered: no slot, no buffer; GETs on gaps
  answer the standard no-such-object response and walks bridge cleanly.
  Returns an `RFC1213Config` record (`registeredCount` + per-OID `ValueCallback*`
  handles) so sketches can verify exactly what registered.
- **Built-in dynamic sysUpTime** — the library now registers
  `.1.3.6.1.2.1.1.3.0` automatically in the `SNMPAgent` constructor as a live
  read-only TimeTicks computed **at request time** (`millis()/10`). Never stale,
  immune to `loop()` stalls, zero sketch code. Cost: exactly 1 pool slot, picked
  up by the derived-sizing math like any other handler.
- **`SNMP_NO_BUILTIN_SYSUPTIME`** — global build flag that removes the built-in
  uptime registration (reclaims the slot; sysUpTime becomes a normal
  sketch-registered OID). Compile-time `static_assert` guards keep the sizing
  honest in both profiles.
- **`SNMPAgent::setUptimeSource()` / `SNMPAgent::uptimeCs()`** — overrideable
  clock source (tests inject a fake clock; hardware can use custom tick
  sources) and the request-time uptime query in TimeTicks.
- **Trap timestamps are automatically correct**: with no sketch callback set,
  `SNMPTrap` resolves its sysUpTime varbind to the library uptime source. GET
  uptime and trap timestamps can never disagree. Sketch callbacks still take
  precedence (pre-v3.3.4 behaviour unchanged).
- Host suite: +35 assertions (210 total, 20 cases) covering constructor
  registration counts, request-time computation with an injected fake clock,
  sparse/full/zero-OID helper selection, loud validation errors (RW string
  `len=0` refused), gap-GET `noSuchObject` behaviour, and registry hygiene.
  New opt-out CI profile: `make ci-test-nobuiltinuptime` (175 assertions green
  under `SNMP_NO_BUILTIN_SYSUPTIME`).
- All five sketches (2 `examples/`, 3 `extras/demos/`) now teach the system
  group: full 6-OID + manual sysObjectID, sysDescr-only minimal, sparse
  3-OID gap demo, sparse + live-uptime, and a zero-system-OID stripped build.

### Changed

- `defs.h` documentation pass: `RFC1213SystemStruct` is now explicitly marked a
  convenience type only (the library never pre-allocates it), and the
  per-OID access comments were corrected to RFC 1213 (sysContact/sysName/
  sysLocation are **Read-Write**, not read-only).
- Demo/example string buffers right-sized 255 B → 64 B (765 B of static RAM
  reclaimed across the three RW system strings in `SNMP_Sensor`).

### Behavioural delta (documented, flag-reversible)

- Builds that previously served an **empty** system subtree now answer
  `sysUpTime` by default. This is the feature — but it is a visible change for
  stripped builds copied forward from v3.3.3. Define
  `SNMP_NO_BUILTIN_SYSUPTIME` to restore the exact prior behaviour.

### Upgrade notes

- No existing sketch changes required, with ONE deliberate exception: a sketch
  that hand-registers its own sysUpTime (addTimestampHandler on
  `.1.3.6.1.2.1.1.3.0`) will now get a **loud registration refusal** (log +
  `nullptr` return) because the built-in already owns that OID — the first
  registration serves GETs, so the duplicate would be dead state. Define
  `SNMP_NO_BUILTIN_SYSUPTIME` (global build flag) and keep your own handler if
  you want sketch-owned uptime. Also raise `SNMP_MAX_CALLBACKS_PER_AGENT` by 1
  to account for the built-in slot in tight budgets.

### Fixed

- PlatformIO strict builds (`-Werror=empty-body`): braced the logging `else`
  branches in the helper so disabled-log builds stay warning-clean on GCC.
- ESP32 type strictness: the helper's sysServices parameter is `int*`
  (matching `addIntegerHandler`); `int32_t*` does not convert on ESP32 where
  `int32_t` is `long`.
