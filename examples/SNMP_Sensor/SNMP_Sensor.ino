#if defined(ESP8266)
    #include <ESP8266WiFi.h> // ESP8266 Core WiFi Library
#else
    #include <WiFi.h> // ESP32 Core WiFi Library
#endif

/* -------------------------------------------------------------------------- *
 * MEMORY MODEL — nothing to configure for this sketch
 *
 *   The library auto-tunes itself for ESP8266 ("_SNMP_ESP8266_TINY" profile)
 *   and DERIVES its ASN pool size at compile time from the number of handlers
 *   you register (SNMP_MAX_CALLBACKS_PER_AGENT) plus the worst-case transient
 *   demand of the configured caps. The arena is locked in as one contiguous
 *   block in the SNMPAgent constructor — before setup() and WiFi — so packet
 *   handling performs zero per-packet heap traffic and cannot fragment the
 *   heap. On ESP8266 the derived TINY defaults for this sketch's profile are:
 *       SNMP_MAX_VARBINDS                        6
 *       SNMP_MAX_CALLBACKS_PER_AGENT            24
 *       SNMP_POOL_ASN_OBJECTS  (derived)        84 x 288 B, locked at boot
 *
 *   !! SIZE OVERRIDES AND THE ONE-DEFINITION RULE !!
 *   Never #define size flags (SNMP_MAX_CALLBACKS_PER_AGENT, SNMP_POOL_*,
 *   OCTET_TYPE_MAX_LENGTH, ...) inside a sketch file: they change CLASS
 *   LAYOUT, so a sketch-only #define makes the sketch and the compiled
 *   library disagree about object sizes -> undefined behaviour (on ESP8266:
 *   instant reboot loops). Set them as GLOBAL build flags so every
 *   translation unit agrees:
 *       arduino-cli:  --build-flags "-DSNMP_MAX_CALLBACKS_PER_AGENT=64"
 *       platformio :  build_flags = -DSNMP_MAX_CALLBACKS_PER_AGENT=64
 *
 *   Handler budget: the ESP8266 TINY profile caps registrations at 24.
 *   This sketch registers 33 OIDs across three MIB groups, so the 18-OID
 *   ENTITY-MIB physical row is compiled in only on non-TINY targets (the
 *   RFC1213 system group and the ENTITY-SENSOR-MIB values remain on all).
 * -------------------------------------------------------------------------- */

#include <WiFiUdp.h>
#include <SNMP_Embedded.h>

#include <LittleFS.h>
#define FILESYSTEM LittleFS

#if defined(ESP8266)
    #define FS_BEGIN()    FILESYSTEM.begin()
    #define SNMP_RAND()   ((uint32_t)os_random())
#elif defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
    #define FS_BEGIN()    FILESYSTEM.begin(FORMAT_LITTLEFS_IF_FAILED)
    #define SNMP_RAND()   esp_random()
#endif

#include <ArduinoJson.h> // Saved data will be stored in JSON

#define FORMAT_LITTLEFS_IF_FAILED true // Be careful, this will wipe all the data stored. So you may want to set this to false once used once.

//************************************
//* Your WiFi info                   *
//************************************
const char* ssid = "SSID";
const char* password = "PASSWORD";
//************************************

//************************************
//* SNMP Configuration               *
//************************************
const char* rocommunity = "public";  // Read only community string
const char* rwcommunity = "private"; // Read Write community string for set commands

// RFC1213-MIB (System)
const char* oidSysDescr = ".1.3.6.1.2.1.1.1.0";    // OctetString SysDescr
const char* oidSysObjectID = ".1.3.6.1.2.1.1.2.0"; // OctetString SysObjectID
const char* oidSysUptime = ".1.3.6.1.2.1.1.3.0";   // TimeTicks sysUptime (hundredths of seconds)
const char* oidSysContact = ".1.3.6.1.2.1.1.4.0";  // OctetString SysContact
const char* oidSysName = ".1.3.6.1.2.1.1.5.0";     // OctetString SysName
const char* oidSysLocation = ".1.3.6.1.2.1.1.6.0"; // OctetString SysLocation
const char* oidSysServices = ".1.3.6.1.2.1.1.7.0"; // Integer sysServices

/* Versioned sysDescr served on .1.3.6.1.2.1.1.1.0 — filled in setup() with the
   running library version so `snmpget` confirms the exact build during hardware
   testing. 64 B leaves room for the version string; handler keeps the pointer. */
static char sysDescr[64] = "SNMP Agent";
char sysObjectID[] = "";
uint32_t sysUptime = 0;
char sysContactValue[255];
char *sysContact = sysContactValue;
char sysNameValue[255];
char *sysName = sysNameValue;
char sysLocationValue[255];
char *sysLocation = sysLocationValue;
int sysServices = 65;

// ENTITY-MIB .1.3.6.1.2.1.47 - Needs to be implemented to support ENTITY-SENSOR-MIB
// An entry would be required per sensor. This is index 1.

// entityPhysicalTable
const char* oidentPhysicalIndex_1 = ".1.3.6.1.2.1.47.1.1.1.1.1.1";
const char* oidentPhysicalDescr_1 = ".1.3.6.1.2.1.47.1.1.1.1.2.1";
const char* oidentPhysicalVendorType_1 = ".1.3.6.1.2.1.47.1.1.1.1.3.1";
const char* oidentPhysicalContainedIn_1 = ".1.3.6.1.2.1.47.1.1.1.1.4.1";
const char* oidentPhysicalClass_1 = ".1.3.6.1.2.1.47.1.1.1.1.5.1";
const char* oidentPhysicalParentRelPos_1 = ".1.3.6.1.2.1.47.1.1.1.1.6.1";
const char* oidentPhysicalName_1 = ".1.3.6.1.2.1.47.1.1.1.1.7.1";
const char* oidentPhysicalHardwareRev_1 = ".1.3.6.1.2.1.47.1.1.1.1.8.1";
const char* oidentPhysicalFirmwareRev_1 = ".1.3.6.1.2.1.47.1.1.1.1.9.1";
const char* oidentPhysicalSoftwareRev_1 = ".1.3.6.1.2.1.47.1.1.1.1.10.1";
const char* oidentPhysicalSerialNum_1 = ".1.3.6.1.2.1.47.1.1.1.1.11.1";
const char* oidentPhysicalMfgName_1 = ".1.3.6.1.2.1.47.1.1.1.1.12.1";
const char* oidentPhysicalModelName_1 = ".1.3.6.1.2.1.47.1.1.1.1.13.1";
const char* oidentPhysicalAlias_1 = ".1.3.6.1.2.1.47.1.1.1.1.14.1";
const char* oidentPhysicalAssetID_1 = ".1.3.6.1.2.1.47.1.1.1.1.15.1";
const char* oidentPhysicalIsFRU_1 = ".1.3.6.1.2.1.47.1.1.1.1.16.1";
const char* oidentPhysicalMfgDate_1 = ".1.3.6.1.2.1.47.1.1.1.1.17.1";
const char* oidentPhysicalUris_1 = ".1.3.6.1.2.1.47.1.1.1.1.18.1";

int entPhysicalIndex_1 = 1;
char entPhysicalDescr_1[] = "Fake Temperature Sensor";
char entPhysicalVendorType_1[] = "";
int entPhysicalContainedIn_1 = 0;
int entPhysicalClass_1 = 8;
int entPhysicalParentRelPos_1 = -1;
char entPhysicalName_1[] = "";
char entPhysicalHardwareRev_1[] = "";
char entPhysicalFirmwareRev_1[] = "";
char entPhysicalSoftwareRev_1[] = "";
char entPhysicalSerialNum_1[] = "";
char entPhysicalMfgName_1[] = "";
char entPhysicalModelName_1[] = "";
char entPhysicalAlias_1[] = "";
char entPhysicalAssetID_1[] = "";
int entPhysicalIsFRU_1 = 0;
char entPhysicalMfgDate_1[] = "'0000000000000000'H";
char entPhysicalUris_1[] = "";

// EntityPhysicalGroup

// ENTITY-SENSOR-MIB .1.3.6.1.2.1.99
// An entry would be required per sensor. This is index 1.
// Must match index in ENTITY-MIB
const char* oidentPhySensorType_1 = ".1.3.6.1.2.1.99.1.1.1.1.1";
const char* oidentPhySensorScale_1 = ".1.3.6.1.2.1.99.1.1.1.2.1";
const char* oidentPhySensorPrecision_1 = ".1.3.6.1.2.1.99.1.1.1.3.1";
const char* oidentPhySensorValue_1 = ".1.3.6.1.2.1.99.1.1.1.4.1";
const char* oidentPhySensorOperStatus_1 = ".1.3.6.1.2.1.99.1.1.1.5.1";
const char* oidentPhySensorUnitsDisplay_1 = ".1.3.6.1.2.1.99.1.1.1.6.1";
const char* oidentPhySensorValueTimeStamp_1 = ".1.3.6.1.2.1.99.1.1.1.7.1";
const char* oidentPhySensorValueUpdateRate_1 = ".1.3.6.1.2.1.99.1.1.1.8.1";

int entPhySensorType_1 = 8;       // Celsius
int entPhySensorScale_1 = 9;      // Units
int entPhySensorPrecision_1 = 0;
int entPhySensorValue_1 = 0;      // Value to be updated
int entPhySensorOperStatus_1 = 1; // OK
char entPhySensorUnitsDisplay_1[] = "Celsius";
uint32_t entPhySensorValueTimeStamp_1 = 0;
int entPhySensorValueUpdateRate_1 = 0; // Unknown at declaration, set later.
//************************************

//************************************
//* Initialise                       *
//************************************
// Global Variables
static const unsigned long UPTIME_UPDATE_INTERVAL = 1000; // ms = 1 second
static unsigned long lastUptimeUpdateTime = 0;
static const unsigned long SENSOR_UPDATE_INTERVAL = 5000; // ms = 5 Seconds
static unsigned long lastSensorUpdateTime = 0;
const char* savedValuesFile = "/SNMP.json";
// SNMP Objects
WiFiUDP udp;
// SNMPAgent snmp = SNMPAgent(rocommunity, rwcommunity); // Creates an SMMPAgent instance with the community strings defined
SNMPAgent snmp = SNMPAgent(rocommunity, rwcommunity); // Creates an SMMPAgent instance
//************************************

//************************************
//* Function declarations            *
//************************************
void addRFC1213MIBHandler();
void addENTITYMIBHandler();
void addENTITYSENSORMIBHandler();
int getUptime();
bool loadSNMPValues();
bool saveSNMPValues();
int readFakeSensor();
uint64_t uptimeMillis();
void printFile(const char* filename);
//************************************

void setup()
{
    Serial.begin(115200);

    // Hardware-test banner: confirm the flashed library version in the serial monitor
    Serial.printf("SNMP_Embedded v%s\n", snmp.getVersion());

    if (!FS_BEGIN())
    {
        Serial.println("LittleFS Mount Failed");
        return;
    }
    WiFi.begin(ssid, password);
    Serial.println("");
    // Wait for connection
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }
    Serial.println("");
    Serial.print("Connected to SSID: ");
    Serial.println(ssid);
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());

    // give snmp a pointer to the UDP object
    snmp.setUDP(&udp);
    snmp.begin();

    // Fill sysDescr (.1.3.6.1.2.1.1.1.0) with the version string, queryable from the
    // SNMP terminal: snmpget -v 2c -c public <IP> .1.3.6.1.2.1.1.1.0
    snprintf(sysDescr, sizeof(sysDescr), "SNMP_Sensor demo (SNMP_Embedded v%s)", snmp.getVersion());

    addRFC1213MIBHandler();      // RFC1213-MIB (System) — 7 OIDs
#ifndef _SNMP_ESP8266_TINY
    addENTITYMIBHandler();       // ENTITY-MIB — 18 OIDs; needs the 64-handler
                                 // default profile (ESP8266 TINY caps at 24)
#endif
    addENTITYSENSORMIBHandler(); // ENTITY-SENSOR-MIB — 8 OIDs

    // Read previously stored values, if any.
    if (loadSNMPValues())
    {
        Serial.println(F("Loaded stored values"));
        printFile(savedValuesFile);
    }

    // Ensure to sortHandlers after adding/removing OID callbacks - this makes snmpwalk work
    snmp.sortHandlers();
}

void loop()
{
    // put your main code here, to run repeatedly:
    snmp.loop(); // This must be called as often as possible to process incoming requests
    if (snmp.setOccurred)
    {
        Serial.println("A Set event has occured.");
        saveSNMPValues(); // Store the values
        snmp.resetSetOccurred();
    }
    // Periodically update Uptime. Don't need to update it on every loop as it can interfere with responding to SNMP requests
    if (millis() - lastUptimeUpdateTime >= UPTIME_UPDATE_INTERVAL)
    {
        lastUptimeUpdateTime += UPTIME_UPDATE_INTERVAL;
        sysUptime = getUptime();
    }
    // Read Sensor Values
    if (millis() - lastSensorUpdateTime >= SENSOR_UPDATE_INTERVAL)
    {
        lastSensorUpdateTime += SENSOR_UPDATE_INTERVAL;
        entPhySensorValue_1 = readFakeSensor();
        entPhySensorValueTimeStamp_1 = sysUptime;
    }
}

int readFakeSensor()
{
    int min = -50;
    int max = 100;
    return min + (int)(SNMP_RAND() % (uint32_t)((max + 1) - min));
}

#if defined(ESP32)
uint64_t uptimeMillis()
{
    return (esp_timer_get_time() / 1000);
}
#else
uint64_t uptimeMillis()
{
    // https://arduino.stackexchange.com/questions/12587/how-can-i-handle-the-millis-rollover
    static uint32_t low32, high32;
    uint32_t new_low32 = millis();
    if (new_low32 < low32)
        high32++;
    low32 = new_low32;
    return (uint64_t)high32 << 32 | low32;
}
#endif

int getUptime()
{
    return (int)(uptimeMillis() / 10); // Convert milliseconds to timeticks (hundredths of a second)
}

// Prints the content of a file to the Serial
void printFile(const char* filename)
{
    // Open file for reading
    File file = FILESYSTEM.open(filename, "r");
    if (!file)
    {
        Serial.println(F("Failed to read file"));
        return;
    }
    Serial.println("SNMP saved values file: ");
    // Extract each characters by one by one
    while (file.available())
    {
        Serial.print((char)file.read());
    }
    Serial.println();
    file.close();
}

bool loadSNMPValues()
{
    File file = FILESYSTEM.open(savedValuesFile, "r");
    if (!file)
    {
        Serial.println(F("Failed to read saved values file"));
        return false;
    }
    size_t size = file.size();
    if (size > 1024)
    {
        Serial.print(F("Stored SNMP values file too large"));
        file.close();
        return false;
    }
    StaticJsonDocument<1024> doc;
    // Deserialize the JSON document
    DeserializationError error = deserializeJson(doc, file);
    if (error)
    {
        Serial.print(F("deserializeJson() failed: "));
        Serial.println(error.f_str());
        file.close();
        return false;
    }
    // Fetch values
    strlcpy(sysContact, doc["sysContact"], sizeof(sysContactValue));
    strlcpy(sysName, doc["sysName"], sizeof(sysNameValue));
    strlcpy(sysLocation, doc["sysLocation"], sizeof(sysLocationValue));
    file.close();
    return true;
}

bool saveSNMPValues()
{

    File file = FILESYSTEM.open(savedValuesFile, "w");
    if (!file)
    {
        Serial.println(F("Failed to open saved values file for writing"));
        return false;
    }
    StaticJsonDocument<1024> doc;
    // Store the values in the JSON document
    doc["sysContact"] = sysContact;
    doc["sysName"] = sysName;
    doc["sysLocation"] = sysLocation;

    // Serialize JSON to file
    if (serializeJson(doc, file) == 0)
    {
        Serial.println(F("Failed to save values to file"));
        file.close();
        return false;
    }
    file.close();
    printFile(savedValuesFile);
    return true;
}

void addRFC1213MIBHandler()
{
    // Add SNMP Handlers of correct type to each OID
    snmp.addReadOnlyStaticStringHandler(oidSysDescr, sysDescr);
    snmp.addReadOnlyStaticStringHandler(oidSysObjectID, sysObjectID);
    snmp.addIntegerHandler(oidSysServices, &sysServices);
    snmp.addTimestampHandler(oidSysUptime, &sysUptime);
    // Add Settable Handlers
    // NOTE: maxLength = sizeof(_buf) matches the 255-byte storage declared above,
    // so SET operations via SNMP and strlcpy() from persistent storage agree on the
    // same maximum string length.
    snmp.addReadWriteStringHandler(oidSysContact,  &sysContact,  sizeof(sysContactValue),  true);
    snmp.addReadWriteStringHandler(oidSysName,     &sysName,     sizeof(sysNameValue),     true);
    snmp.addReadWriteStringHandler(oidSysLocation, &sysLocation, sizeof(sysLocationValue), true);
}

void addENTITYMIBHandler()
{
    snmp.addIntegerHandler(oidentPhysicalIndex_1, &entPhysicalIndex_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalDescr_1, entPhysicalDescr_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalVendorType_1, entPhysicalVendorType_1);
    snmp.addIntegerHandler(oidentPhysicalContainedIn_1, &entPhysicalContainedIn_1);
    snmp.addIntegerHandler(oidentPhysicalClass_1, &entPhysicalClass_1);
    snmp.addIntegerHandler(oidentPhysicalParentRelPos_1, &entPhysicalParentRelPos_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalName_1, entPhysicalName_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalHardwareRev_1, entPhysicalHardwareRev_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalFirmwareRev_1, entPhysicalFirmwareRev_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalSoftwareRev_1, entPhysicalSoftwareRev_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalSerialNum_1, entPhysicalSerialNum_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalMfgName_1, entPhysicalMfgName_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalModelName_1, entPhysicalModelName_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalAlias_1, entPhysicalAlias_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalAssetID_1, entPhysicalAssetID_1);
    snmp.addIntegerHandler(oidentPhysicalIsFRU_1, &entPhysicalIsFRU_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalMfgDate_1, entPhysicalMfgDate_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalUris_1, entPhysicalUris_1);
}

void addENTITYSENSORMIBHandler()
{
    entPhySensorValueUpdateRate_1 = SENSOR_UPDATE_INTERVAL;

    snmp.addIntegerHandler(oidentPhySensorType_1, &entPhySensorType_1);
    snmp.addIntegerHandler(oidentPhySensorScale_1, &entPhySensorScale_1);
    snmp.addIntegerHandler(oidentPhySensorPrecision_1, &entPhySensorPrecision_1);
    snmp.addIntegerHandler(oidentPhySensorValue_1, &entPhySensorValue_1);
    snmp.addIntegerHandler(oidentPhySensorOperStatus_1, &entPhySensorOperStatus_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhySensorUnitsDisplay_1, entPhySensorUnitsDisplay_1);
    snmp.addTimestampHandler(oidentPhySensorValueTimeStamp_1, &entPhySensorValueTimeStamp_1);
    snmp.addIntegerHandler(oidentPhySensorValueUpdateRate_1, &entPhySensorValueUpdateRate_1);
}