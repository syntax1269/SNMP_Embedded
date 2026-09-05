/*
 * SNMP_Embedded minimal demo — dual-build (esp8266 + esp32 via PlatformIO)
 * Target:    pio run --environment esp8266 / pio run --environment esp32
 * Purpose:   Minimal end-to-end demo: fill in WiFi credentials, flash,
 *            and poll the OIDs below with net-snmp from any machine.
 *
 * Uses #if macro dispatch so a single .ino file compiles against both
 * ESP8266WiFi.h (Espressif 8266 core) and WiFi.h (Espressif 32 core).
 *
 * Before flashing: fill in WIFI_SSID / WIFI_PASSWORD below, then
 *   pio run -t upload -e esp8266   OR   pio run -t upload -e esp32
 *   pio device monitor -b 115200
 *
 * Test from another machine once the IP prints to serial:
 *   snmpget      -v 2c -c public  <ip> .1.3.6.1.4.1.5.0
 *   snmpset      -v 2c -c private <ip> .1.3.6.1.4.1.5.0 i 99
 *   snmpbulkwalk -v 2c -c public  <ip> .1.3.6.1.4.1.5
 */

#if defined(ESP8266)
#  include <ESP8266WiFi.h>
#else
#  include <WiFi.h>
#endif

#include <WiFiUdp.h>
#include <SNMP_Embedded.h>

#define WIFI_SSID     "your-ssid-here"
#define WIFI_PASSWORD "your-pass-here"

/* NOTE: never #define library size flags (SNMP_MAX_CALLBACKS_PER_AGENT,
 * SNMP_POOL_*, OCTET_TYPE_MAX_LENGTH, ...) inside a sketch source file. They
 * change CLASS LAYOUT, so a sketch-only #define makes this TU and the compiled
 * library disagree about object sizes -> undefined behaviour (on ESP8266:
 * instant reboot loops). Set them in platformio.ini `build_flags` (global to
 * every TU), e.g. `-DSNMP_MAX_CALLBACKS_PER_AGENT=16`. This demo needs no
 * overrides: the library auto-sizes its pools from the number of handlers you
 * register, locks the arena in at boot, and serves requests with zero
 * per-packet heap traffic. */

// The UDP socket the agent listens on. The agent calls udp.begin(161) itself
// inside begin() — you only need to hand it over with setUDP().
static WiFiUDP udp;

static SNMPAgent agent = SNMPAgent("public", "private");

static int      myInteger = 42;                  // SETtable via snmpset
static char     sensorName[] = "PlatformIO-Sensor";
static uint32_t counter32 = 0;

static uint32_t getUptimeSeconds(void) { return (uint32_t)(millis() / 1000U); }

void setup()
{
    Serial.begin(115200);
    delay(500);
    Serial.println();
#if defined(ESP8266)
    Serial.printf("SNMP_Embedded v%s minimal demo (ESP8266 / PlatformIO)\n", agent.getVersion());
#else
    Serial.printf("SNMP_Embedded v%s minimal demo (ESP32 / PlatformIO)\n", agent.getVersion());
#endif

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(200);
        Serial.print('.');
    }
    Serial.println();
    Serial.print("IP: "); Serial.println(WiFi.localIP());

    // REQUIRED wiring: UDP socket first, then bind + start listening.
    agent.setUDP(&udp);
    agent.begin();

    // ZERO RFC1213 system OIDs is a valid posture: this demo registers no
    // system group at all, so the pool holds exactly the custom handlers
    // below (+1 slot for the library's built-in sysUpTime; define
    // SNMP_NO_BUILTIN_SYSUPTIME as a global build flag to reclaim even that).
    // To add a system group later, one call does it:
    //   agent.addRFC1213SystemGroup(sysDescrBuf);
    // Three representative handlers (integer / static string / dynamic timestamp).
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
