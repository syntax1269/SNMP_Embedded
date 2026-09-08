# Changelog — SNMP_Embedded

## v3.4.4 — P1 runtime/high-water statistics (blueprint Phase 1)

### Added
- **`SNMP_RuntimeStats`** (public struct) + **`SNMPAgent::getRuntimeStats(SNMP_RuntimeStats*)`**:
  pool fields (used / high-water / cap — live reads) and monotonic packet
  counters since boot: `packets_received`, `packets_rejected` (valid parse,
  community denied), `malformed_packets` (parse failed), `too_big_responses`
  (RFC 3416 tooBig answered), `allocation_failures` (pool-exhausted
  `asn_new`), `double_release_errors`. The deterministic-resource philosophy
  is now observable from any sketch — no logging required.
- **`SNMP_ENGINE_MAX_RAM_BYTES`**: compile-time constant for the maximum RAM
  this library instance can consume (pool arena + packet buffer + worst-case
  varbind array) — completes the P0 bounded-memory proof as a single number
  per configuration, with a build-time `static_assert` sanity check.
- Six new host test cases `[snmp][v344]`: valid traffic leaves counters at
  baseline; malformed / rejected / tooBig / allocation-failure each move
  exactly their own counter; `getRuntimeStats` snapshot correctness incl.
  `packets_received` through a feeding-UDP `loop()`; the bounded-RAM constant
  sanity. The mock UDP stub is now virtual so tests can feed datagrams.

### Counting contract (both packet paths)
- `malformed_packets` and `packets_rejected` are mutually exclusive (a packet
  is either a parse failure or a community denial, never both).
- `too_big_responses` is counted at the RFC 3416 tooBig **decisions** (GetBulk
  expansion cap, response-fit rebuild), not by return code — a genErr response
  shares `SNMP_ERROR_PACKET_SENT`, so return-code counting would conflate them.
- `allocation_failures` counts pool-exhausted `asn_new` calls (counted before
  the host-test heap fallback, so the event is recorded on every build).
- Both the zero-copy and classic paths increment the same counters at the same
  points; the same test file asserts +1 deltas under both profiles.

### Validation
- Host matrix: default **2,193 assertions / 38 cases**, zero-copy-off **330 / 33**,
  no-builtin-uptime **2,125 / 33**, no-traps **2,111 / 33** — all green.
- Fuzz (ASAN/UBSAN): unchanged green — 20,014 inputs, zero runtime errors.

## v3.4.3 — P0 parser fuzzing (blueprint Phase 3): two real decoder bugs found and fixed

### Added
- **Standalone deterministic fuzz harness** (`tests/fuzz/fuzz_parser.cpp`, targets
  `make fuzz` / `make fuzz-asan`): hammers both packet paths (`handlePacket`
  classic + `handlePacketInPlace` zero-copy), the `snmp_ber_peek_packet` view
  walk, and the container `fromBuffer` decode with a 14-kind structured
  adversarial corpus (truncated/invalid BER, corrupt length fields, deep TLV
  nesting, invalid OIDs, huge integers, malformed SET/GETBULK, all-0xFF,
  all-0x00, random garbage) plus seeded mutation campaigns.  After every input
  it verifies the blueprint invariants: no crash, no hang, no OOB read/write,
  input buffer never mutated, pool returns to its registered-handler baseline.
  Deterministic (fixed default seed, `--seed`/`--cases`/`--maxlen` flags);
  ASAN+UBSAN build runs the same corpus.  Wired into CI after the host suite.
- **Regression tests** for the two findings below (`[snmp][v343][fuzz]`).

### Fixed (both found by the fuzzer)
- **F1 — unbounded BER length-field read (out-of-bounds).**
  `decode_ber_length_integer()` read the long-form length field with no bound
  check: a header like `02 94` (long form claiming 20 length bytes) made it
  read up to 127 bytes past the caller's buffer on the container path.  The
  decoder now rejects length fields that run off the buffer, use the
  indefinite form, or exceed 4 length bytes (> 2^32-1 content) — the same
  strictness `ber_decode_length()` in the zero-copy path already had.
- **F2 — invalid SNMP_VERSION enum cast (undefined behaviour, UBSan).**
  A hostile version integer (e.g. 0xFFFFFFFF) was cast to the `SNMP_VERSION`
  enum *before* the range check; the enum load itself was UB.  The raw
  integer is now validated against `[0, SNMP_VERSION_MAX)` first, then cast.

### Validation
- Fuzzer: 20,014 inputs per run (14 corpora x both paths + view walk + container
  decode) green; six seeds x 50k mutations @ 1400 B budget green under
  ASAN+UBSAN with zero runtime errors.
- Host matrix: default **2,170 assertions / 32 cases**, zero-copy-off **307 / 27**,
  no-builtin-uptime **2,103 / 27**, no-traps **2,089 / 27** — all green.

## v3.4.2 — True zero-heap packet path (AsnPtr)

### Fixed
- **Report_001 finding #1 — the "zero heap" claim was not actually true.** Every
  `std::shared_ptr` in the packet hot path wrapped a pool-allocated object with
  a custom deleter, but each construction still heap-allocated a control block
  (~16–32 B). A p768 GET response paid ~9–11 control blocks per packet; the
  classic (zero-copy-off) path paid ~10× that. At flood rates that is ~100+
  malloc/free pairs per second on an ESP8266.

### Added
- **`AsnPtr<T>`** (`BER.h`): move-only, single-ownership pointer whose destructor
  routes through the existing `asn_delete`. Zero heap, zero new pool metadata —
  the pool's occupancy machinery *is* the ownership record. Move-only makes the
  former bug class (pool address handed to `delete`) structurally impossible.
  Covered by 25 new unit tests including the stale-`bulkFreed` tolerance
  contract carried over from the v3.3.3 hardware campaign.
- **`buildTypeWithValueRaw()`** (protected virtual on `ValueCallback`): the
  optimized factory that returns a pool-owning `AsnPtr<BER_CONTAINER>` directly.
  The old `buildTypeWithValue()` stays as a deprecated bridge: an external
  subclass still overriding it works unchanged, at the cost of one control
  block per GET (its `shared_ptr` is deep-cloned into pool storage). Removal
  earmarked for the next major.
- **Per-packet heap-allocation census** (host suite, `[v342]` tag): a scoped
  global `operator new` counter proves **0 heap allocations per
  GET/SET/GETNEXT/GETBULK on both packet paths**, with pool-drift assertions
  after every window. The harness DIAG gained a per-tick `hdiff` heap-delta
  readout (net drift detector on hardware).

### Changed
- All packet-path shared_ptr construction sites migrated: the 12
  `ValueCallback` factories, `SNMPPacket` header fields + parse-time varbind
  cloning (now raw pool clones), `SNMPPDUHandler` response assembly,
  `SNMPZeroCopy` decode/response staging, and the trap/inform varbind list.
  The unused `shared_ptr generateVarBindList()` virtual was removed (zero
  callers); `OIDType::cloneRaw()` is the single clone path. `OIDType::equals()`
  gained a raw-pointer overload — the shared_ptr-by-value form implicitly
  constructed a control block per comparison.

### Validation
- Host matrix: default **2,167 assertions / 30 cases**, zero-copy-off **304 / 25**,
  no-builtin-uptime **2,099 / 25**, no-traps **2,085 / 25** — all green.
- Census before/after: zero-copy GET 11→**0**, SET 9→**0**, GETNEXT 9→**0**,
  GETBULK 2→**0**; classic GET 94→**0**, SET 87→**0**, GETNEXT 94→**0**,
  GETBULK 42→**0**.
- Hardware (ESP8266 ESP-01, p768): 1-min flood **183 ops / 0 fails**, 5-min flood
  **903 ops / 0 fails**, pool 27/33 throughout, **`hdiff_avg=0`** (zero net heap
  drift across ~1.1M ticks), 0 alarms / 0 crashes / 0 reboots, banner
  `hwtest_3.4.2-p768` proven on the wire.

## v3.4.1 — SNMP_NO_TRAPS: compile-time trap/inform removal

### Added
- **`SNMP_NO_TRAPS` global build flag** (default `0`, permanent public flag, all MCUs).
  Compiles the entire trap/inform subsystem out of the binary:
  - the `SNMPTrap` class becomes a loud stub — any instantiation fails to compile
    with a message naming the flag and the remedy;
  - `sendTrapTo()`, `markTrapDeleted()`, `setInformAckCallback()`, the inform retry
    queue and the inform-ack machinery are compiled out of the agent;
  - the pool formula drops the 16-slot trap-tree term:
    `pool = 2*SNMP_MAX_VARBINDS + 4 + SNMP_MAX_CALLBACKS_PER_AGENT`
    (13-handler 768-B profile: 25 slots instead of 33).
- `test-notraps` host profile (CI: `ci-test-notraps`) — the full suite minus the
  five trap/inform cases, plus a formula case with `static_assert` proof that the
  trap-tree term is zero and the pool derivation is exact.
- `#error` guard: `SNMP_NO_TRAPS=1` together with `SNMP_TRAP_VB_RESERVE > 0`
  fails at build time (contradictory configuration).

### Fixed
- tests Makefile object-dir collision: `BUILD_DIR=./build-<profile>` profile builds
  compile objects into `tests/src/` (the `../src` in the object path escapes the
  build dir), so two profile builds run back-to-back silently reused each other's
  objects. Every non-default profile target now clears the shared directory first
  (CI on clean checkouts was unaffected; local back-to-back runs were not).

### Validation
- Host matrix: default **2,125 assertions / 28 cases**, zero-copy-off **262 / 23**,
  no-builtin-uptime **2,057 / 23**, no-traps **2,043 / 23** — all green; default
  counts identical to v3.4.0 (flag-off is behavior-identical).
- Loud-failure probe: instantiating `SNMPTrap` under the flag fails at compile
  time with the flag named in the message.
- Hardware (ESP8266 ESP-01, standardized flood harness, flag off): 1-min and
  5-min unpaced soaks PASS — pool 27/33, heap floor 32,496 B, frag ≤1 %,
  0 alarms / 0 crashes / 0 reboots.


## v3.4.0 — Zero-copy packet path + exact-pricing pool formula

**No public API changes. Existing sketches compile and behave identically.**
Wire behavior is byte-verified identical to v3.3.6 (host equivalence suite,
byte-for-byte response comparison across GET / GETNEXT / GETBULK / SET / error paths).

### Added

- **Zero-copy packet path** (default): inbound packets are parsed in place over
  the UDP buffer (`BerView` TLV walk — no per-varbind OID containers, no
  dotted-string renders); responses are written directly into the outgoing UDP
  buffer (`BerWriter`, with atomic TLV writes and a *measured* — not worst-case —
  response-size fit check, so `tooBig` is answered only when genuinely true).
  Handler dispatch matches raw encoded-OID bytes (`memcmp`) — exactly the bytes
  that define sort order, so walk semantics are exact.
- **`SNMP_ZERO_COPY=0`** global build flag: restores the classic container path
  unchanged (field escape hatch; kept compiling in CI as `make test-nozc`).
- **`SNMP_TRAP_VB_RESERVE`** global build flag (default 0): sketches that attach
  varbinds to traps reserve 3 pool slots per trap varbind. Unreserved overflow
  fails loudly (pool-exhausted log, trap not sent) — same behavior as all
  previous releases for >4-varbind traps.
- Host suite grew from 262 assertions / 23 cases to **2,125 assertions / 28
cases** (fixture-corpus equivalence, BerWriter byte-equivalence, staged zc
handler parity, tooBig boundaries).

### Changed

- **Pool formula: exact pricing** (replaces the worst-case-estimated formula).
  Every slot is charged to a named, source-verified consumer:

  ```
  pool = max( 2*SNMP_MAX_VARBINDS , 16 + 3*SNMP_TRAP_VB_RESERVE )   // worst tick
       + 4                                                          // explicit idle margin
       + SNMP_MAX_CALLBACKS_PER_AGENT                               // permanent handlers
  ```

  Request tick = VB decoded + response value containers (2·VB); trap tick =
  the minimal v2c trap tree (16 slots: 4 envelope + 5 PDU header + 7 mandatory
  varbinds — counted line-by-line in the source). A single-threaded agent never
  overlaps the two, so the worst tick is the larger, not the sum. Queued informs
  hold **zero** pool slots (stateless design — proven on hardware with the
  inform queue saturated under flood).

- `SNMP_MAX_VARBINDS` and the response budget are unchanged; no capacity flags
  moved in this release (one variable at a time — the slot savings are banked
  as measured heap headroom).

### Measured on hardware (ESP8266 ESP-01, standardized flood harness, full CSV history)

| Metric | v3.3.6 | v3.4.0 | Delta |
|---|---|---|---|
| Pool cap (13-handler profile, both packet budgets) | 57 / 79 | **33 / 33** | −42% / −58% |
| Pool peak under flood+SET+walk+inform-stress | 57 (saturated) | **27** | −53% |
| Idle slots at modeled worst tick | 0 | 4 | exact margin |
| Free heap at boot, 768-B profile | 28,632 B | **35,736 B** | **+7.1 KB (+25%)** |
| Free heap at boot, 1400-B profile | 21,424 B | **35,040 B** | **+13.6 KB (+64%)** |
| Sustained request throughput (interval-paced soak) | 2.35 ops/s | 2.91–3.03 ops/s | **+24–28%** |
| Flash (IROM), 768-B profile | 307,360 B | 301,936 B | −5.4 KB |
| Alarms / crashes / reboots (all soaks) | 0 | 0 | parity |
| SET round-trip integrity | 100% | 100% | parity |

Hardware validation: per profile, 1-minute, 5-minute, and 15-minute flood soaks
(bulkwalk + wide-walk-tooBig + GETNEXT + SET + sysDescr mix), plus a dedicated
inform-queue-saturation stress profile; 0 pool alarms, 0 crashes, 0 reboots
across the entire campaign.

### Internal

- Phase-gated development with measured decision gates: Strategy A/B OID-matching
  benchmark (A: memcmp won 3–4.6× with far lower stack cost; B removed),
  BerWriter byte-equivalence proof, staged response plans (all request slices
  staged before any response byte is written — immune to buffer aliasing),
  worst-tick calibration stress probe, and a fully source-cited pool formula.

---

## v3.3.6 — Sketch-facing inform delivery confirmation (`setInformAckCallback`)

**Additive API. No breaking changes; the inform state machine's behavior without a callback is unchanged.**

### Added

- **`SNMPAgent::setInformAckCallback(informAckCB cb)`** — first-class inform
  delivery confirmation for sketches. The library has always matched the
  manager's Response PDU (by request ID) against its pending-inform queue;
  this surfaces that event to user code:

  ```cpp
  void onInformAck(unsigned long requestID, bool success) { /* ... */ }
  snmp.setInformAckCallback(onInformAck);   // nullptr to uninstall
  ```

  - Fired from **inside `snmp.loop()`** (never an ISR, no thread concerns).
  - `success=true`: the manager decoded and processed the inform with
    `noError` (RFC 3416 Response PDU, errorStatus 0).
  - `success=false`: the manager responded with an **error** status — the
    inform was *rejected*, not lost. The pending item is retired either way
    (no resend after an explicit answer).
  - **Only fires for request IDs with a pending inform** — unsolicited or
    stale Response PDUs can never produce phantom confirmations.
  - Informs that exhaust their retries with **no response at all** do not
    fire the ack (nothing arrived to acknowledge); the item is retired when
    the retry budget runs out, as before.
- New typedef `informAckCB` (`void (*)(snmp_request_id_t, bool)`) in
  `SNMPParser.h`.
- Host tests: ack delivered for matched responses, success/failure outcome
  propagation, phantom suppression for unmatched responses, uninstall
  restores silence, queue consumed on ack (262 assertions / 23 cases default;
  194/18 with `SNMP_NO_BUILTIN_SYSUPTIME`).

### Notes

- The callback is per-agent (each `SNMPAgent` instance carries its own hook);
  multi-agent sketches install one per instance.
- Compile matrix re-verified: all examples/demos on ESP8266 + ESP32.

## v3.3.5 — Auto-size RFC1213 helper: pass the buffer, not the sizeof

**Additive API polish. The v3.3.4 pointer+len form remains valid; no breaking changes.**

### Added

- **Auto-size overloads for `addRFC1213SystemGroup()`** — pass the RW string
  **arrays** directly (`sysContactBuf`, not `&sysContactPtr, sizeof(buf)`); the
  library deduces each capacity from the array type. The call drops from 8
  arguments to 5 and no `sizeof()` trivia:
  `snmp.addRFC1213SystemGroup(sysDescr, sysContactBuf, sysNameBuf, sysLocBuf, &sysServices);`
- **`RFC1213_SKIP` sentinel** — skip an OID in the auto-size form by placing the
  sentinel in its slot (`RFC1213_SKIP` instead of an array). Replaces the
  pointer form's `nullptr, 0` pair with a single self-documenting token.
- **`StringBufCallback`** — array-backed RW string handler binding the `char[]`
  buffer directly; semantics identical to `StringCallback` (GET serves buffer
  contents, SET `strncpy`s bounded by the deduced capacity, over-long SETs
  answer `WRONG_LENGTH`). Zero allocation.
- **Type-safety by construction**: `SysBuf` accepts real arrays or `RFC1213_SKIP`
  and *not* bare `char*` — a pointer with unknown capacity fails to compile
  rather than guessing. The advanced pointer+len overload remains for heap or
  runtime-sized storage.

### Changed

- All five sketches/examples updated to teach the auto-size form (the teaching
  matrix now shows auto-size, SKIP, and the side-by-side pointer form in
  `SNMP_Sensor`).
- Host suite grows to **243 assertions / 22 test cases**: auto-size GET/SET
  round-trip, SKIP semantics, deduced-capacity overflow refusal, and pointer-
  form interop. Opt-out profile unchanged (175 / 17, both exit 0).
- Compile matrix re-verified 8/8 (2 examples × 2 platforms + 2 CLI demos +
  PlatformIO minimal × 2 envs). Hardware re-verified on ESP8266: clean boot,
  1-minute flood soak (104 ops, 0 pool alarms, 0 crashes, 1 WiFi transport
  timeout).

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
