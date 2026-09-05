/*
 * SNMP_Embedded minimal demo — ESP8266
 * Target:    arduino-cli compile --fqbn esp8266:esp8266:generic
 * Purpose:   Zero-config starting point: fill in WiFi credentials, flash,
 *            and poll the OIDs below with net-snmp from any machine.
 *
 * Wiring:    Serial 115200 baud, GPIO1 TX, GPIO3 RX (ESP8266 pins).
 *
 * Before run:
 *   1. Fill in WIFI_SSID / WIFI_PASSWORD below.
 *   2. Install the esp8266 core via the Arduino CLI board manager.
 *   3. Install this library into <sketchbook>/libraries/SNMP_Embedded
 *      (Arduino-CLI scans for libraries there at compile time).
 *
 * Test from another machine once the IP prints to serial:
 *   snmpget      -v 2c -c public  <ip> .1.3.6.1.4.1.5.0
 *   snmpset      -v 2c -c private <ip> .1.3.6.1.4.1.5.0 i 99
 *   snmpbulkwalk -v 2c -c public  <ip> .1.3.6.1.4.1.5
 */

#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <SNMP_Embedded.h>

#define WIFI_SSID     "your-ssid-here"
#define WIFI_PASSWORD "your-pass-here"

/* NOTE: never #define library size flags (SNMP_MAX_CALLBACKS_PER_AGENT,
 * SNMP_POOL_*, OCTET_TYPE_MAX_LENGTH, ...) inside a sketch file. They change
 * CLASS LAYOUT, so a sketch-only #define makes the sketch and the compiled
 * library disagree about object sizes -> undefined behaviour (on ESP8266:
 * instant reboot loops). Set them as GLOBAL build flags, e.g.
 *   arduino-cli ... --build-flags "-DSNMP_MAX_CALLBACKS_PER_AGENT=16"
 * This demo needs no overrides: the library auto-sizes its pools from the
 * number of handlers you register, locks the arena in at boot, and serves
 * requests with zero per-packet heap traffic. */

// The UDP socket the agent listens on. The agent calls udp.begin(161) itself
// inside begin() — you only need to hand it over with setUDP().
static WiFiUDP udp;

static SNMPAgent agent = SNMPAgent("public", "private");

static int      myInteger = 42;                  // SETtable via snmpset
static char     sensorName[] = "ESP8266-Sensor";
static uint32_t counter32 = 0;

/* RFC1213 system group buffers. Only what you pass gets registered —
 * each registered OID = 1 pool slot + its buffer; gaps answer
 * noSuchName (v1) / noSuchObject (v2c) and walks bridge them. */
static char sysDescrBuf[64]   = "ESP8266 minimal demo (SNMP_Embedded)";
static char sysNameBuf[64]    = "esp8266-demo";
static char sysLocationBuf[64] = "rack-1";

static uint32_t getUptimeSeconds(void) { return (uint32_t)(millis() / 1000U); }

void setup()
{
    Serial.begin(115200);
    delay(500);
    Serial.println();
    Serial.printf("SNMP_Embedded v%s minimal demo (ESP8266)\n", agent.getVersion());

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

    // SPARSE system group (v3.3.4 helper): sysDescr + sysName + sysLocation
    // only — sysContact / sysServices are simply not registered (see the
    // RFC1213_SKIP slots below), and sysUpTime is already live via the
    // library's built-in registration. Try the gap yourself:
    //   snmpget -v 2c -c public <ip> .1.3.6.1.2.1.1.4.0   -> noSuchObject
    // v3.3.5: pass the BUFFER ARRAYS — capacity is deduced, no sizeof() needed.
    agent.addRFC1213SystemGroup(
        sysDescrBuf,                       // sysDescr (read-only static string)
        RFC1213_SKIP,                      // sysContact  — not configured
        sysNameBuf,                        // sysName     (read-write, size deduced)
        sysLocationBuf,                    // sysLocation (read-write, size deduced)
        nullptr);                          // sysServices — not configured

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
