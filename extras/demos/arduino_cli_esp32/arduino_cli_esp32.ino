/*
 * SNMP_Embedded minimal demo — ESP32
 * Target:    arduino-cli compile --fqbn esp32:esp32:esp32
 * Purpose:   Zero-config starting point: fill in WiFi credentials, flash,
 *            and poll the OIDs below with net-snmp from any machine.
 *
 * Before run:
 *   1. Fill in WIFI_SSID / WIFI_PASSWORD below.
 *   2. Install the esp32 core via the Arduino CLI board manager.
 *   3. Install this library into <sketchbook>/libraries/SNMP_Embedded
 *      (Arduino-CLI scans for libraries there at compile time).
 *
 * Test from another machine once the IP prints to serial:
 *   snmpget      -v 2c -c public  <ip> .1.3.6.1.4.1.5.0
 *   snmpset      -v 2c -c private <ip> .1.3.6.1.4.1.5.0 i 99
 *   snmpbulkwalk -v 2c -c public  <ip> .1.3.6.1.4.1.5
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <SNMP_Embedded.h>

#define WIFI_SSID     "your-ssid-here"
#define WIFI_PASSWORD "your-pass-here"

/* NOTE: never #define library size flags (SNMP_MAX_CALLBACKS_PER_AGENT,
 * SNMP_POOL_*, OCTET_TYPE_MAX_LENGTH, ...) inside a sketch file. They change
 * CLASS LAYOUT, so a sketch-only #define makes the sketch and the compiled
 * library disagree about object sizes -> undefined behaviour. Set them as
 * GLOBAL build flags, e.g.
 *   arduino-cli ... --build-flags "-DSNMP_MAX_CALLBACKS_PER_AGENT=16"
 * This demo needs no overrides: the library auto-sizes its pools from the
 * number of handlers you register, locks the arena in at boot, and serves
 * requests with zero per-packet heap traffic. */

// The UDP socket the agent listens on. The agent calls udp.begin(161) itself
// inside begin() — you only need to hand it over with setUDP().
static WiFiUDP udp;

static SNMPAgent agent = SNMPAgent("public", "private");

static int      myInteger = 42;                  // SETtable via snmpset
static char     sensorName[] = "ESP32-Sensor";
static uint32_t counter32 = 0;

/* RFC1213 system group buffers (sparse selection — see setup()). */
static char sysDescrBuf[64]   = "ESP32 minimal demo (SNMP_Embedded)";
static char sysContactBuf[64] = "ops@example.com";
static char* sysContactPtr = sysContactBuf;

static uint32_t getUptimeSeconds(void) { return (uint32_t)(millis() / 1000U); }

void setup()
{
    Serial.begin(115200);
    delay(500);
    Serial.println();
    Serial.printf("SNMP_Embedded v%s minimal demo (ESP32)\n", agent.getVersion());

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(200);
        Serial.print('.');
    }
    Serial.println();
    Serial.print(F("IP: ")); Serial.println(WiFi.localIP());

    // REQUIRED wiring: UDP socket first, then bind + start listening.
    agent.setUDP(&udp);
    agent.begin();

    // SPARSE system group (v3.3.4 helper): sysDescr + sysContact only.
    // You NEVER maintain uptime yourself — sysUpTime is registered by the
    // library automatically and computed at request time, so it is current
    // even right after a loop() stall. Check it twice a second apart:
    //   snmpget -v 2c -c public <ip> .1.3.6.1.2.1.1.3.0
    agent.addRFC1213SystemGroup(
        sysDescrBuf,                           // sysDescr (read-only static string)
        &sysContactPtr, sizeof(sysContactBuf), // sysContact (read-write)
        nullptr, 0,                            // sysName     — not configured
        nullptr, 0,                            // sysLocation — not configured
        nullptr);                              // sysServices — not configured

    // Three representative custom handlers (integer / static string / dynamic timestamp).
    agent.addIntegerHandler(".1.3.6.1.4.1.5.0", &myInteger, true);
    agent.addReadOnlyStaticStringHandler(".1.3.6.1.4.1.5.1", sensorName);
    agent.addDynamicReadOnlyTimestampHandler(".1.3.6.1.4.1.5.2", getUptimeSeconds);
    agent.addCounter32Handler(".1.3.6.1.4.1.5.3", &counter32);

    // Keep walk order correct after registering handlers.
    agent.sortHandlers();

    Serial.println(F("SNMP agent started. try:"));
    Serial.println(F("  snmpget      -v 2c -c public  <ip> .1.3.6.1.4.1.5.0"));
    Serial.println(F("  snmpset      -v 2c -c private <ip> .1.3.6.1.4.1.5.0 i 99"));
    Serial.println(F("  snmpbulkwalk -v 2c -c public  <ip> .1.3.6.1.4.1.5"));
}

void loop()
{
    agent.loop();   // must be called as often as possible

    static unsigned long lastTick = 0;
    if (millis() - lastTick > 1000UL) {
        lastTick = millis();
        counter32++;   // demo counter: +1 per second
    }
}
