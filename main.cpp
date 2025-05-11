#include <ESP8266WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <base64.h>
#include <LittleFS.h>
#include <string.h>
#include <Hash.h>
#include <Crypto.h>
#include <SHA256.h>
#include <base64.h>
#include <CRC32.h>      // استفاده از کتابخانه CRC32 برای ESP8266
#include <TimeLib.h>    // ^1.6.1
#include <MD5Builder.h> // Part of ESP8266 core for MD5
#include <Ticker.h>     // Required for Ticker class
#include <map>
#include "TaskScheduler.h"
#include "TimeSync.h"

// Create a global task scheduler
TaskScheduler scheduler;
// --- Configuration ---
#define WATCHDOG_TIMEOUT_MS 10000                                                     // Watchdog timeout in milliseconds
#define LOG_BUFFER_SIZE 32                                                            // Size of the circular log buffer
#define JWT_SECRET "78754cecc4a4f227ca34766840b58a60d620a8fae88fe9ce347230552edb008d" // IMPORTANT: Change this!
#define JWT_EXPIRY_SECONDS 3600                                                       // JWT expiry time in seconds (1 hour)
#define ADMIN_USERNAME "admin"                                                        // Default admin username
#define ADMIN_PASSWORD "password"                                                     // Default admin password - CHANGE THIS!
#define NTP_SERVER "pool.ntp.org"                                                     // NTP server address
#define TIME_SYNC_INTERVAL_MS 3600000                                                 // Time sync interval (1 hour)
#define SYSTEM_CREDENTIALS_FILE "/system_config.json"

#define SESSION_FILE "/sessions.json"
// Define the preferences file path
#define PREFERENCES_FILE "/preferences.json"

#define DATABASE_FILE "/database.bin"

// Max number of concurrent sessions
#define MAX_SESSIONS 5

#define MAX_JSON_SIZE 512

const char *ssid = "POCO F3";
const char *password = "Mehdi@13681";

// JWT Secret (Use a strong random key in production)
const char *jwt_secret = "76da54384e9d6f1f9449e769f45e34930d99aec629314481ed2c1b754f458cdc";

// Token expiration time in milliseconds (default: 24 hour)
const unsigned long TOKEN_EXPIRATION = 3600000;

struct FileUploadMeta
{
  size_t size;
  unsigned long startTime;
  MD5Builder md5;
};

// --- System Status and Logging ---
struct SystemStatus
{
  unsigned long uptime_seconds = 0;
  size_t free_heap = 0;
  size_t min_free_heap = (size_t)-1; // Initialize with max value
  uint8_t wifi_status = WL_DISCONNECTED;
  time_t current_time = 0;
  size_t fs_total_bytes = 0;
  size_t fs_used_bytes = 0;
};

struct LogEntry
{
  unsigned long timestamp;
  String message;
};

// --- WiFi Configuration ---
struct SystemCredentials
{
  String AdminUsername;
  String AdminPassword;
  String DeviceName;
  String apSSID;
  String apPassword;
  bool WorkingMode;
  bool isDeviceConfig = true;
};

unsigned long restartTimer = 0;
bool shouldRestart = false;
String activeToken = "";

// Session management
struct UserSession
{
  String token;
  unsigned long expiryMillis;    // زمان انقضا نسبی
  unsigned long createdAtMillis; // زمان ساخت نسبی
  String username;
};

Ticker watchdogTicker;
// Create global TimeSync instance
TimeSync timeSync;

volatile unsigned long lastWatchdogReset = 0;
volatile bool watchdogTriggered = false; // Ticker for resetting the watchdog

SystemCredentials sysCredentials;
SystemStatus systemStatus;
// Circular buffer for logs
char logBuffer[LOG_BUFFER_SIZE][64]; // Store up to LOG_BUFFER_SIZE messages, each max 63 chars + null terminator
int logBufferHead = 0;
int logBufferTail = 0; // Tail points to the next empty slot
bool logBufferFull = false;

UserSession sessions[MAX_SESSIONS];

static AsyncWebServer server(80);
static AsyncAuthenticationMiddleware digestAuth;
String collectedData;

// --- JWT & Session Prototypes ---
String getUniqueTokenId();
String calculateHMACSHA256(const String &data, const String &key);
String generateJWT(String username);
bool validateJWT(String token, String &username);
String getAuthToken(AsyncWebServerRequest *request);
String createJWT(String username);
String getAuthToken(AsyncWebServerRequest *request);
bool checkSession(String token);
bool saveSessionsToFile();
String base64URLEncode(const String &input);
String base64URLDecode(const String &input);
// --- Watchdog Prototypes ---
void setupWatchdog();
void resetWatchdog();
void checkWatchdog();
void recoverFromWatchdog();
void emergencyMode();
// --- System Prototypes ---
void systemLog(const char *format, ...);
void updateSystemStatus();
void setupTimeSynchronization();
void updateTimeSynchronization();
bool loadSystemCredentials();
bool saveSystemCredentials();
// -- File Management Prototypes ---
String generateDatabaseHash(uint8_t *data, size_t length);
// -- WebServer Prototypes ---
void setupWebServer();

// --- Watchdog Implementation ---
void setupWatchdog()
{
  systemLog("Setting up enhanced watchdog timer...");

  // Store the initial time
  lastWatchdogReset = millis();

  // Check watchdog status every second
  watchdogTicker.attach(1.0, checkWatchdog);

  // Configure ESP8266 hardware watchdog timer (typically 3-8 seconds)
  ESP.wdtEnable(WATCHDOG_TIMEOUT_MS);

  systemLog("Watchdog timer setup complete.");
}
void checkWatchdog()
{
  // Software watchdog implementation
  unsigned long now = millis();
  if (now - lastWatchdogReset > WATCHDOG_TIMEOUT_MS)
  {
    // Software watchdog triggered
    watchdogTriggered = true;
    systemLog("WATCHDOG: Main loop appears frozen!");

    // Try to recover
    recoverFromWatchdog();

    // Reset software watchdog
    lastWatchdogReset = now;
  }

  // Feed hardware watchdog
  ESP.wdtFeed();
}
void resetWatchdog()
{
  // Update last reset time
  lastWatchdogReset = millis();
  // Feed hardware watchdog
  ESP.wdtFeed();
}
void recoverFromWatchdog()
{
  static int watchdogEvents = 0;
  watchdogEvents++;

  systemLog("Attempting recovery from watchdog event #%d", watchdogEvents);

  if (watchdogEvents < 3)
  {
    // Try to recover WiFi if disconnected
    if (WiFi.status() != WL_CONNECTED)
    {
      systemLog("Recovery: Reconnecting WiFi");
      WiFi.disconnect();
      delay(500);
      WiFi.begin(sysCredentials.apSSID.c_str(), sysCredentials.apPassword.c_str());
    }

    // Free memory if critically low
    if (ESP.getFreeHeap() < 4096)
    {
      systemLog("Recovery: Low memory condition detected");
      // Close any open files, reset buffers, etc.
    }
  }
  else if (watchdogEvents < 5)
  {
    // More aggressive recovery - restart subsystems
    systemLog("Recovery: Restarting critical subsystems");
    // Restart web server
    server.end();
    delay(500);
    setupWebServer();
  }
  else
  {
    // Give up and restart
    systemLog("Recovery: Too many watchdog events, restarting device");
    ESP.restart();
  }
}
// -------------------------------
// --- Logging System (Circular Buffer) ---
void systemLog(const char *format, ...)
{
  // Use a statically allocated buffer to avoid memory fragmentation
  static char tempBuffer[64];

  va_list args;
  va_start(args, format);
  vsnprintf(tempBuffer, sizeof(tempBuffer), format, args);
  va_end(args);

  // Copy to the circular buffer with bounds checking
  strncpy(logBuffer[logBufferTail], tempBuffer, sizeof(logBuffer[logBufferTail]) - 1);
  logBuffer[logBufferTail][sizeof(logBuffer[logBufferTail]) - 1] = '\0';

  // Update buffer pointers with atomic operations if threading concerns exist
  int newTail = (logBufferTail + 1) % LOG_BUFFER_SIZE;

  if (newTail == logBufferHead)
  {
    logBufferFull = true;
    logBufferHead = (logBufferHead + 1) % LOG_BUFFER_SIZE;
  }

  logBufferTail = newTail;

  // Also print to Serial for debugging
  Serial.println(tempBuffer);
}
//-------------------------------------------
// --- System Status Update ---
void updateSystemStatus()
{
  systemStatus.uptime_seconds = millis() / 1000;
  systemStatus.free_heap = ESP.getFreeHeap();
  systemStatus.min_free_heap = min(systemStatus.min_free_heap, systemStatus.free_heap);
  systemStatus.wifi_status = WiFi.status();
  systemStatus.current_time = now(); // Get time from TimeLib

  FSInfo fs_info;
  LittleFS.info(fs_info);
  systemStatus.fs_total_bytes = fs_info.totalBytes;
  systemStatus.fs_used_bytes = fs_info.usedBytes;
}
// --- System Credentials Management ---
bool loadSystemCredentials()
{
  systemLog("Loading System credentials...");
  if (LittleFS.exists(SYSTEM_CREDENTIALS_FILE))
  {
    File file = LittleFS.open(SYSTEM_CREDENTIALS_FILE, "r");
    if (file)
    {
      StaticJsonDocument<256> jsonDoc;
      DeserializationError error = deserializeJson(jsonDoc, file);
      file.close();

      if (!error)
      {
        sysCredentials.DeviceName = jsonDoc["DeviceName"].as<String>();
        sysCredentials.AdminUsername = jsonDoc["AdminUsername"].as<String>();
        sysCredentials.AdminPassword = jsonDoc["AdminPassword"].as<String>();
        sysCredentials.apSSID = jsonDoc["apSSID"].as<String>();
        sysCredentials.apPassword = jsonDoc["apPassword"].as<String>();
        sysCredentials.isDeviceConfig = jsonDoc["isDeviceConfig"].as<bool>();
        sysCredentials.WorkingMode = jsonDoc["WorkingMode"].as<bool>();
        systemLog("System credentials loaded.");
        return true;
      }
      else
      {
        systemLog("Failed to parse System credentials JSON.");
      }
    }
    else
    {
      systemLog("Failed to open System credentials file for reading.");
    }
  }
  else
  {
    systemLog("System credentials file not found.");
  }
  return false;
}
bool saveSystemCredentials()
{
  systemLog("Saving WiFi credentials to file...");
  File file = LittleFS.open(SYSTEM_CREDENTIALS_FILE, "w");
  if (file)
  {
    StaticJsonDocument<200> jsonDoc;
    jsonDoc["AdminUsername"] = sysCredentials.AdminUsername;
    jsonDoc["AdminPassword"] = sysCredentials.AdminPassword;
    jsonDoc["apSSID"] = sysCredentials.apSSID;
    jsonDoc["apSSID"] = sysCredentials.apPassword;
    jsonDoc["DeviceName"] = sysCredentials.DeviceName;
    jsonDoc["isDeviceConfig"] = sysCredentials.isDeviceConfig;
    jsonDoc["WorkingMode"] = sysCredentials.WorkingMode;

    if (serializeJson(jsonDoc, file) > 0)
    {
      file.close();
      systemLog("WiFi credentials saved successfully.");
      return true;
    }
    else
    {
      file.close();
      systemLog("Failed to write WiFi credentials JSON to file.");
    }
  }
  else
  {
    systemLog("Failed to open WiFi credentials file for writing.");
  }
  return false;
}
//-------------------------------------------------
/**
 * Generate a database hash from binary data
 * Uses MD5 for fast and reliable verification
 */
String generateDatabaseHash(uint8_t *data, size_t length)
{
  MD5Builder md5;
  md5.begin();
  md5.add(data, length);
  md5.calculate();

  // Get MD5 hash
  String md5Hash = md5.toString();

  // Return formatted hash including data length
  return "md5-" + md5Hash + "-" + String(length);
}
void setupFileSystem()
{
  systemLog("Initializing LittleFS...");

  // Try mounting up to 3 times
  int attempts = 0;
  bool fsOK = false;

  while (!fsOK && attempts < 3)
  {
    fsOK = LittleFS.begin();
    if (!fsOK)
    {
      attempts++;
      systemLog("LittleFS mount failed, attempt %d/3", attempts);
      delay(500);
    }
  }

  if (!fsOK)
  {
    systemLog("LittleFS could not mount after multiple attempts. Formatting...");

    // Format with more severe recovery options if needed
    // e.g., using custom format options if available
    if (LittleFS.format())
    {
      systemLog("LittleFS formatted successfully.");
      if (!LittleFS.begin())
      {
        systemLog("CRITICAL: LittleFS mount failed after formatting!");
        // In production, consider some fallback mechanism
        // Like a factory reset or fallback operation mode
      }
      else
      {
        systemLog("LittleFS initialized successfully after formatting.");
      }
    }
    else
    {
      systemLog("CRITICAL: LittleFS formatting failed!");
      // Enter emergency mode
      emergencyMode();
    }
  }
  else
  {
    systemLog("LittleFS initialized successfully.");
    // Check filesystem health
    FSInfo fs_info;
    if (LittleFS.info(fs_info))
    {
      float usedPercent = (fs_info.usedBytes * 100.0) / fs_info.totalBytes;
      systemLog("FS: %.1f%% used (%u/%u bytes)",
                usedPercent, fs_info.usedBytes, fs_info.totalBytes);

      // Warn if filesystem is nearly full
      if (usedPercent > 90)
      {
        systemLog("WARNING: Filesystem is nearly full (%.1f%%)", usedPercent);
      }
    }
  }
}
void emergencyMode()
{
  systemLog("ENTERING EMERGENCY MODE - File system unavailable");
  // Minimal operation mode - perhaps offering only configuration functionality
  WiFi.mode(WIFI_AP);
  WiFi.softAP("ESP_EMERGENCY", "");

  AsyncWebServer emergencyServer(80);
  emergencyServer.on("/", HTTP_GET, [](AsyncWebServerRequest *request)
                     { request->send(200, "text/html",
                                     "<html><body>"
                                     "<h1>ESP8266 Emergency Mode</h1>"
                                     "<p>File system error detected. Please try:</p>"
                                     "<ul><li><a href='/format'>Format File System</a></li>"
                                     "<li><a href='/restart'>Restart Device</a></li></ul>"
                                     "</body></html>"); });

  emergencyServer.on("/format", HTTP_GET, [](AsyncWebServerRequest *request)
                     {
        request->send(200, "text/html", "Formatting file system... Device will restart.");
        // Schedule format and restart
        Ticker restartTimer;
        restartTimer.once(1, []() {
            LittleFS.format();
            ESP.restart();
        }); });

  emergencyServer.on("/restart", HTTP_GET, [](AsyncWebServerRequest *request)
                     {
        request->send(200, "text/html", "Restarting device...");
        Ticker restartTimer;
        restartTimer.once(1, []() {
            ESP.restart();
        }); });

  emergencyServer.begin();
}
//---------------------------------------------------------
String createJWT(String username)
{
  // Use a proper JWT library or implement HMAC-SHA256 signing
  MD5Builder md5;
  md5.begin();

  // Create header
  String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
  String base64Header = base64URLEncode(header);

  // Create payload
  unsigned long issueTime = now();
  unsigned long expiryTime = issueTime + JWT_EXPIRY_SECONDS;

  StaticJsonDocument<256> payloadDoc;
  payloadDoc["sub"] = username;
  payloadDoc["iat"] = issueTime;
  payloadDoc["exp"] = expiryTime;
  payloadDoc["jti"] = getUniqueTokenId(); // Add unique token ID to prevent replay attacks

  String payloadJson;
  serializeJson(payloadDoc, payloadJson);
  String base64Payload = base64URLEncode(payloadJson);

  // Create signature
  String dataToSign = base64Header + "." + base64Payload;
  String signature = calculateHMACSHA256(dataToSign, JWT_SECRET);
  String base64Signature = base64URLEncode(signature);

  String token = base64Header + "." + base64Payload + "." + base64Signature;
  systemLog("Generated JWT for user: %s", username.c_str());
  return token;
}
// Helper function for base64URL encoding (RFC 4648)
String base64URLEncode(const String &input)
{
  String base64 = "";
  for (size_t i = 0; i < input.length(); i += 3)
  {
    uint32_t n = ((uint8_t)input[i] << 16) | ((i + 1 < input.length() ? (uint8_t)input[i + 1] : 0) << 8) | (i + 2 < input.length() ? (uint8_t)input[i + 2] : 0);
    base64 += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(n >> 18) & 63];
    base64 += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(n >> 12) & 63];
    base64 += (i + 1 < input.length() ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(n >> 6) & 63] : '=');
    base64 += (i + 2 < input.length() ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[n & 63] : '=');
  }
  base64.replace("+", "-");
  base64.replace("/", "_");
  base64.replace("=", "");
  return base64;
}
// HMAC-SHA256 implementation - use a crypto library if available
String calculateHMACSHA256(const String &data, const String &key)
{
  // This is a placeholder - use a crypto library with HMAC-SHA256 support
  // For example, the Crypto or Cryptosuite library
  // If a library isn't available, you need to implement HMAC-SHA256

  // For demonstration only:
  MD5Builder md5;
  md5.begin();
  md5.add(key + data);
  md5.calculate();
  return md5.toString(); // NOT secure! Replace with actual HMAC-SHA256
}

// A unique token ID to prevent replay attacks
String getUniqueTokenId()
{
  String uniqueId = String(ESP.getChipId(), HEX) + String(millis());
  MD5Builder md5;
  md5.begin();
  md5.add(uniqueId);
  md5.calculate();
  return md5.toString().substring(0, 8);
}

const char *getMimeType(const String &path)
{
  // Convert path to lowercase for case-insensitive comparison
  String lowerPath = path;
  lowerPath.toLowerCase();

  // Check for common web file formats
  if (lowerPath.endsWith(".html") || lowerPath.endsWith(".htm"))
    return "text/html";
  if (lowerPath.endsWith(".css"))
    return "text/css";
  if (lowerPath.endsWith(".js"))
    return "application/javascript";
  if (lowerPath.endsWith(".json"))
    return "application/json";
  if (lowerPath.endsWith(".xml"))
    return "application/xml";
  if (lowerPath.endsWith(".txt"))
    return "text/plain";
  if (lowerPath.endsWith(".ico"))
    return "image/x-icon";
  if (lowerPath.endsWith(".gif"))
    return "image/gif";
  if (lowerPath.endsWith(".png"))
    return "image/png";
  if (lowerPath.endsWith(".jpg") || lowerPath.endsWith(".jpeg"))
    return "image/jpeg";
  if (lowerPath.endsWith(".webp"))
    return "image/webp";
  if (lowerPath.endsWith(".svg"))
    return "image/svg+xml";
  if (lowerPath.endsWith(".ttf"))
    return "font/ttf";
  if (lowerPath.endsWith(".woff"))
    return "font/woff";
  if (lowerPath.endsWith(".woff2"))
    return "font/woff2";
  if (lowerPath.endsWith(".eot"))
    return "application/vnd.ms-fontobject";
  if (lowerPath.endsWith(".otf"))
    return "font/otf";
  if (lowerPath.endsWith(".pdf"))
    return "application/pdf";
  if (lowerPath.endsWith(".zip"))
    return "application/zip";
  if (lowerPath.endsWith(".mp3"))
    return "audio/mpeg";
  if (lowerPath.endsWith(".wav"))
    return "audio/wav";
  if (lowerPath.endsWith(".mp4"))
    return "video/mp4";
  if (lowerPath.endsWith(".webm"))
    return "video/webm";

  // Handle GZIP compressed files by checking the extension before .gz
  if (lowerPath.endsWith(".gz"))
  {
    String uncompressedPath = lowerPath.substring(0, lowerPath.length() - 3); // Remove .gz
    if (uncompressedPath.endsWith(".css"))
      return "text/css";
    if (uncompressedPath.endsWith(".js"))
      return "application/javascript";
    if (uncompressedPath.endsWith(".html") || uncompressedPath.endsWith(".htm"))
      return "text/html";
    if (uncompressedPath.endsWith(".json"))
      return "application/json";
    if (uncompressedPath.endsWith(".xml"))
      return "application/xml";
    if (uncompressedPath.endsWith(".txt"))
      return "text/plain";
    if (uncompressedPath.endsWith(".ico"))
      return "image/x-icon";
    if (uncompressedPath.endsWith(".gif"))
      return "image/gif";
    if (uncompressedPath.endsWith(".png"))
      return "image/png";
    if (uncompressedPath.endsWith(".jpg") || uncompressedPath.endsWith(".jpeg"))
      return "image/jpeg";
    if (uncompressedPath.endsWith(".webp"))
      return "image/webp";
    if (uncompressedPath.endsWith(".svg"))
      return "image/svg+xml";
    if (uncompressedPath.endsWith(".ttf"))
      return "font/ttf";
    if (uncompressedPath.endsWith(".woff"))
      return "font/woff";
    if (uncompressedPath.endsWith(".woff2"))
      return "font/woff2";
    if (uncompressedPath.endsWith(".eot"))
      return "application/vnd.ms-fontobject";
    if (uncompressedPath.endsWith(".otf"))
      return "font/otf";
    if (uncompressedPath.endsWith(".pdf"))
      return "application/pdf";
  }

  // Default MIME type for unknown files
  return "application/octet-stream";
}

// Base64 URL-safe decode - fixed implementation
String base64URLDecode(const String &input)
{
  // Replace URL-safe characters with standard Base64 characters
  String base64Str = input;
  base64Str.replace("-", "+");
  base64Str.replace("_", "/");

  // Add padding if needed
  while (base64Str.length() % 4 != 0)
  {
    base64Str += "=";
  }

  // Calculate the decoded length (approximately 3/4 of the base64 string)
  int decodedLength = base64Str.length() * 3 / 4;
  unsigned char *buffer = new unsigned char[decodedLength + 1]; // +1 for null terminator

  // Decode using the base64 library with correct parameter order
  size_t outputLength = base64::decode(base64Str.c_str(), buffer, decodedLength);
  buffer[outputLength] = '\0'; // Ensure null termination

  String result = String((char *)buffer);
  delete[] buffer;

  return result;
}
// Generate JWT token
String generateJWT(String username)
{
  // Create header
  StaticJsonDocument<200> header;
  header["alg"] = "HS256";
  header["typ"] = "JWT";

  String headerStr;
  serializeJson(header, headerStr);
  String encodedHeader = base64URLEncode(headerStr);

  // Create payload
  StaticJsonDocument<200> payload;
  payload["username"] = username;
  payload["exp"] = millis() + TOKEN_EXPIRATION;
  payload["iat"] = millis();

  String payloadStr;
  serializeJson(payload, payloadStr);
  String encodedPayload = base64URLEncode(payloadStr);

  // Create signature
  String data = encodedHeader + "." + encodedPayload;

  SHA256 sha256;
  sha256.reset();
  sha256.update((const uint8_t *)data.c_str(), data.length());
  sha256.update((const uint8_t *)jwt_secret, strlen(jwt_secret));
  uint8_t hash[32];
  sha256.finalize(hash, sizeof(hash));
  String signature = base64::encode(hash, sizeof(hash));
  String encodedSignature = base64URLEncode(signature);

  // Construct JWT token
  return encodedHeader + "." + encodedPayload + "." + encodedSignature;
}
// Validate JWT token and extract username - improved implementation
bool validateJWT(String token, String &username)
{
  // Serial.println("Validating JWT token: " + token);

  // Split token into parts
  int firstDot = token.indexOf('.');
  int lastDot = token.lastIndexOf('.');

  if (firstDot == -1 || lastDot == -1 || firstDot == lastDot)
  {
    // Serial.println("Invalid token format: missing or misplaced dots");
    return false;
  }

  String encodedHeader = token.substring(0, firstDot);
  String encodedPayload = token.substring(firstDot + 1, lastDot);
  String receivedSignature = token.substring(lastDot + 1);

  // Debug output
  // Serial.println("Header (encoded): " + encodedHeader);
  // Serial.println("Payload (encoded): " + encodedPayload);

  // Verify signature using the same method as in generateJWT
  String data = encodedHeader + "." + encodedPayload;

  SHA256 sha256;
  sha256.reset();
  sha256.update((const uint8_t *)data.c_str(), data.length());
  sha256.update((const uint8_t *)jwt_secret, strlen(jwt_secret));
  uint8_t hash[32];
  sha256.finalize(hash, sizeof(hash));
  String signature = base64::encode(hash, sizeof(hash));
  String expectedSignature = base64URLEncode(signature);

  if (receivedSignature != expectedSignature)
  {
    // Serial.println("Signature verification failed");
    // Serial.println("Expected: " + expectedSignature);
    // Serial.println("Received: " + receivedSignature);
    return false;
  }

  // Parse payload
  String payloadStr = base64URLDecode(encodedPayload);
  // Serial.println("Decoded payload: " + payloadStr);

  // Use a larger buffer for the JSON document to handle potential larger payloads
  StaticJsonDocument<512> payload;
  DeserializationError error = deserializeJson(payload, payloadStr);

  if (error)
  {
    // Serial.println("Failed to parse payload JSON: " + String(error.c_str()));

    // Additional debugging for JSON parsing
    for (size_t i = 0; i < payloadStr.length(); i++)
    {
      Serial.printf("%02X ", payloadStr[i]);
      if ((i + 1) % 16 == 0)
        Serial.println();
    }
    Serial.println();

    return false;
  }

  // Check if required fields exist
  if (!payload.containsKey("username") || !payload.containsKey("exp"))
  {
    // Serial.println("Missing required fields in payload");
    return false;
  }

  // Check expiration
  unsigned long expTime = payload["exp"];
  unsigned long currentTime = millis();

  if (currentTime > expTime)
  {
    Serial.println("Token has expired");
    Serial.println("Current time: " + String(currentTime));
    Serial.println("Expiration time: " + String(expTime));
    return false;
  }

  // Extract username
  username = payload["username"].as<String>();
  // Serial.println("Token validated successfully for user: " + username);
  return true;
}
// Extract token from Authorization header or query parameter
String getAuthToken(AsyncWebServerRequest *request)
{
  // First try to get token from Authorization header (preferred method)
  if (request->hasHeader("Authorization"))
  {
    String authHeader = request->header("Authorization");

    // Check for Bearer token format
    if (authHeader.startsWith("Bearer "))
    {
      String token = authHeader.substring(7); // Remove "Bearer " prefix
      token.trim();                           // Remove any whitespace

      if (token.length() > 0)
      {
        // Serial.println("Token found in Authorization header");
        return token;
      }
    }
  }

  // If no Authorization header, try to get token from query parameter
  if (request->hasParam("token"))
  {
    String token = request->getParam("token")->value();
    token.trim();

    if (token.length() > 0)
    {
      // Serial.println("Token found in query parameter");
      return token;
    }
  }

  // If no token found in header or query parameter, try to get from cookie
  if (request->hasHeader("Cookie"))
  {
    String cookies = request->header("Cookie");
    int tokenStart = cookies.indexOf("token=");

    if (tokenStart != -1)
    {
      tokenStart += 6; // Length of "token="
      int tokenEnd = cookies.indexOf(";", tokenStart);

      // If no semicolon found, take the rest of the string
      if (tokenEnd == -1)
      {
        tokenEnd = cookies.length();
      }

      String token = cookies.substring(tokenStart, tokenEnd);
      token.trim();

      if (token.length() > 0)
      {
        // Serial.println("Token found in cookie");
        return token;
      }
    }
  }
  // No token found
  // Serial.println("No authentication token found");
  return "";
}
String getUsernameFromToken(AsyncWebServerRequest *request)
{
  String token = getAuthToken(request);
  String username;
  if (validateJWT(token, username))
  {
    return username;
  }
  return "";
}
// Check if request has valid authentication
bool isAuthenticated(AsyncWebServerRequest *request)
{
  // Extract token from Authorization header
  String token = getAuthToken(request);
  // Serial.println("Checking authentication for token: " + token);
  //  If no token is provided, authentication fails
  if (token.isEmpty())
  {
    Serial.println("No token provided");
    return false;
  }

  // Validate the JWT token structure and signature
  String username;
  if (!validateJWT(token, username))
  {
    Serial.println("Invalid JWT token");
    return false;
  }

  // Check if the token exists in our session store
  if (!checkSession(token))
  {
    Serial.println("Token not found in active sessions");
    return false;
  }

  // If we got here, the token is valid and exists in our sessions
  // Serial.println("Authentication successful for user: " + username);
  return true;
}
// Add a new session
void addSession(String token, String username)
{
  int emptySlot = -1;
  unsigned long oldestTime = millis();
  int oldestSlot = 0;

  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token == "")
    {
      emptySlot = i;
      break;
    }
    if (sessions[i].expiryMillis < oldestTime)
    {
      oldestTime = sessions[i].expiryMillis;
      oldestSlot = i;
    }
  }

  int slotToUse = (emptySlot != -1) ? emptySlot : oldestSlot;
  unsigned long now = millis();

  sessions[slotToUse].token = token;
  sessions[slotToUse].expiryMillis = now + TOKEN_EXPIRATION;
  sessions[slotToUse].createdAtMillis = now;
  sessions[slotToUse].username = username;

  saveSessionsToFile();
}

// Check if a session exists and is valid
bool checkSession(String token)
{
  unsigned long now = millis();

  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token == token)
    {
      // بررسی انقضای سشن
      if (now > sessions[i].expiryMillis)
      {
        Serial.println("Session expired: " + sessions[i].username);
        // پاکسازی سشن منقضی‌شده
        sessions[i].token = "";
        sessions[i].expiryMillis = 0;
        sessions[i].createdAtMillis = 0;
        sessions[i].username = "";
        saveSessionsToFile(); // آپدیت فایل سشن‌ها
        return false;
      }
      return true; // سشن معتبره
    }
  }

  Serial.println("Session token not found.");
  return false;
}

// Remove expired sessions
void removeExpiredSessions()
{
  unsigned long now = millis();
  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token != "" && now > sessions[i].expiryMillis)
    {
      sessions[i].token = "";
      sessions[i].expiryMillis = 0;
      sessions[i].createdAtMillis = 0;
      sessions[i].username = "";
    }
  }
}

bool saveSessionsToFile()
{
  StaticJsonDocument<1024> doc;
  JsonArray arr = doc.createNestedArray("sessions");

  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token != "")
    {
      JsonObject obj = arr.createNestedObject();
      obj["token"] = sessions[i].token;
      obj["expiry"] = sessions[i].expiryMillis;
      obj["createdAt"] = sessions[i].createdAtMillis;
      obj["username"] = sessions[i].username;
    }
  }

  File file = LittleFS.open(SESSION_FILE, "w");
  if (!file)
  {
    // Serial.println("Failed to open session file for writing");
    return false;
  }

  serializeJson(doc, file);
  file.close();
  Serial.println("Sessions saved to file");
  return true;
}

bool loadSessionsFromFile()
{
  if (!LittleFS.exists(SESSION_FILE))
  {
    Serial.println("No session file found.");
    return false;
  }

  File file = LittleFS.open(SESSION_FILE, "r");
  if (!file)
  {
    Serial.println("Failed to open session file for reading");
    return false;
  }

  StaticJsonDocument<1024> doc;
  DeserializationError error = deserializeJson(doc, file);
  file.close();

  if (error)
  {
    Serial.println("Failed to parse session file");
    return false;
  }

  JsonArray arr = doc["sessions"];
  unsigned long currentMillis = millis();
  int i = 0;

  for (JsonObject obj : arr)
  {
    if (i >= MAX_SESSIONS)
      break;

    String token = obj["token"].as<String>();
    unsigned long createdAt = obj["createdAt"];
    unsigned long storedExpiry = obj["expiry"];
    String username = obj["username"].as<String>();

    // محاسبه زمان باقی‌مانده
    if (storedExpiry <= createdAt)
      continue; // زمان نامعتبر
    unsigned long remaining = storedExpiry - createdAt;
    if (remaining > TOKEN_EXPIRATION)
      continue; // ایمنی

    // بازسازی سشن با زمان نسبی جدید
    sessions[i].token = token;
    sessions[i].createdAtMillis = currentMillis;
    sessions[i].expiryMillis = currentMillis + remaining;
    sessions[i].username = username;
    i++;
  }

  Serial.printf("Loaded %d session(s) from file.\n", i);
  return true;
}

bool logoutUserByToken(String token)
{
  bool found = false;

  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token == token)
    {
      Serial.println("Logging out user: " + sessions[i].username);

      // پاک‌سازی سشن
      sessions[i].token = "";
      sessions[i].expiryMillis = 0;
      sessions[i].createdAtMillis = 0;
      sessions[i].username = "";
      found = true;
      break;
    }
  }

  if (found)
  {
    saveSessionsToFile(); // به‌روزرسانی فایل
  }
  else
  {
    Serial.println("Token not found in active sessions");
  }

  return found;
}

void sendJsonResponse(AsyncWebServerRequest *request, int statusCode, const String &jsonContent)
{
  AsyncWebServerResponse *response = request->beginResponse(statusCode, "application/json", jsonContent);

  // اگر درخواست header با کلید Origin داشت، اون رو بفرست
  if (request->hasHeader("Origin"))
  {
    String origin = request->getHeader("Origin")->value();
    response->addHeader("Access-Control-Allow-Origin", origin); // پاسخ به همان Origin
  }
  else
  {
    response->addHeader("Access-Control-Allow-Origin", "*"); // حالت fallback (امن نیست برای credentials)
  }

  request->send(response);
}

void withAuth(AsyncWebServerRequest *request, std::function<void(String username)> handler)
{
  String clientTime = request->getHeader("X-Client-Time")->value();
  Serial.printf("Received client time: %s\n", clientTime.c_str());

  if (!isAuthenticated(request))
  {
    sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
    return;
  }

  String username;
  String token = getAuthToken(request);
  validateJWT(token, username);

  handler(username);
}

// تابع محاسبه CRC32 برای فایل
String calculateFileCRC32()
{
  File dbFile = LittleFS.open(DATABASE_FILE, "r");
  if (!dbFile)
  {
    return "";
  }
  // محاسبه CRC32
  CRC32 crc;
  while (dbFile.available())
  {
    uint8_t buffer[256];
    size_t bytesRead = dbFile.read(buffer, sizeof(buffer));
    crc.update(buffer, bytesRead);
  }

  dbFile.close();
  // تبدیل مقدار CRC32 به رشته هگزادسیمال 8 کاراکتری
  uint32_t crcValue = crc.finalize();
  char hashStr[9];
  sprintf(hashStr, "%08x", crcValue);

  return String(hashStr);
}

void setupWebServer()
{
  // --- CORS Setup ---
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Client-Time");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Credentials", "true"); // Allow credentials (e.g., cookies, auth headers)

  // Handle root route ("/")
  // If device is not configured, serve config.html at root (no authentication needed initially)
  server.on("/config", HTTP_GET, [](AsyncWebServerRequest *request)
            { request->send(LittleFS, "/config.html", "text/html"); })
      .addMiddleware(&digestAuth);
  // If device is configured, serve index.html at root
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request)
            { 
        // Check if client sent time header
        if (request->hasHeader("X-Client-Time")) {
          String clientTimeStr = request->header("X-Client-Time");
          time_t clientTime = clientTimeStr.toInt();
          // Validate client time (must be reasonably recent)
          if (clientTime > 1600000000) { // After 2020-09-13
            struct timeval tv;
            tv.tv_sec = clientTime;
            tv.tv_usec = 0;
            settimeofday(&tv, NULL);
            
            Serial.print("Time updated from client: ");
            time_t now = time(nullptr);
            Serial.println(ctime(&now));
          }
        }           
    if (!sysCredentials.isDeviceConfig) {
      request->send(LittleFS, "/config.html", "text/html");
    } else {
      request->send(LittleFS, "/index.html", "text/html");
    } });
  //.setAuthentication(localSettings.adminUsername,localSettings.adminPassword,AUTH_DIGEST);
  // Handle configuration route (/config) with authentication when device is configured
  // Handle saving configuration (existing /saveconfig route with redirect)
  server.on("/saveconfig", HTTP_POST, [](AsyncWebServerRequest *request)
            {
              Serial.println("Request received from: " + request->client()->remoteIP().toString());

              // Check if all required parameters are present in the POST data
              if (!request->hasParam("deviceName", true) ||
                  !request->hasParam("adminUsername", true) ||
                  !request->hasParam("adminPassword", true) ||
                  !request->hasParam("deviceMode", true) ||
                  !request->hasParam("apName", true) ||
                  !request->hasParam("apPassword", true))
              {
                request->send(400, "text/plain", "Bad Request: Missing parameters!");
                sysCredentials.isDeviceConfig = 0;
                Serial.println("Bad Request: Missing parameters!");
                return;
              }

              // Get the form parameters
              String deviceName = request->getParam("deviceName", true)->value();
              String adminUsername = request->getParam("adminUsername", true)->value();
              String adminPassword = request->getParam("adminPassword", true)->value();
              String deviceMode = request->getParam("deviceMode", true)->value();
              String apName = request->getParam("apName", true)->value();
              String apPassword = request->getParam("apPassword", true)->value();

              // Validate lengths
              if (deviceName.length() > 32 || adminUsername.length() > 32 || adminPassword.length() > 32 ||
                  apName.length() > 32 || apPassword.length() > 32)
              {
                request->send(400, "text/plain", "Bad Request: Input too long! Max length is 32 characters.");
                sysCredentials.isDeviceConfig = 0;
                return;
              }

              if (deviceName.length() < 4 || adminUsername.length() < 4 || adminPassword.length() < 4 ||
                  apName.length() < 1 || apPassword.length() < 4)
              {
                request->send(400, "text/plain", "Bad Request: Input too short! Min length is 4 characters.");
                sysCredentials.isDeviceConfig = 0;
                return;
              }

              if (apPassword.length() < 8 || apPassword.length() > 32)
              {
                request->send(400, "text/plain", "Bad Request: Access Point Password must be at least 8 characters long or max 32 characters");
                sysCredentials.isDeviceConfig = 0;
                return;
              }

              if (deviceMode != "softAP" && deviceMode != "station")
              {
                request->send(400, "text/plain", "Bad Request: Invalid device mode.");
                sysCredentials.isDeviceConfig = 0;
                return;
              }

              // Update localSettings
              sysCredentials.AdminUsername=adminUsername;
              sysCredentials.AdminPassword=adminPassword;
              sysCredentials.DeviceName=deviceName;
              sysCredentials.apSSID, apName;
              sysCredentials.apPassword=apPassword;
              sysCredentials.WorkingMode = (deviceMode == "station");
              sysCredentials.isDeviceConfig = 1;

              // Save settings to LittleFS
              if (!saveSystemCredentials())
              {
                request->send(500, "text/plain", "Internal Server Error: Failed to save settings!");
                Serial.println("Failed to save settings to LittleFS.");
                return;
              }

              // Send 200 OK with success message
              request->send(200, "text/plain", "Settings saved successfully!");
              Serial.println("Settings saved successfully."); }, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total)
            {
      Serial.printf("Body received, length: %u\n", len);
      String body = String((char*)data);
      Serial.println("Raw body: " + body); });




  /*
    Login Routes and Session Manager
  */

  server.on("/api/login", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
            { sendJsonResponse(request, 204, ""); });

  server.on("/api/login", HTTP_POST, [](AsyncWebServerRequest *request) {}, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total)
            {
              if (total > MAX_JSON_SIZE) {
                sendJsonResponse(request, 413, "{\"error\":\"Payload too large\"}");
                return;
              }
    // Handle the JSON login request
    String body = String((char*)data).substring(0, len);
    StaticJsonDocument<200> doc;
    DeserializationError error = deserializeJson(doc, body);
    
    if (error) {
      sendJsonResponse(request, 400, "{\"error\":\"Invalid JSON\"}");
      return;
    }
  
    String username = doc["username"].as<String>();
    String password = doc["password"].as<String>();
    Serial.printf("Received login request: username=%s, password=%s\n", username.c_str(), password.c_str());
  
    if (username == "admin" && password == "admin") {
      String token = generateJWT(username);
      addSession(token, username);
  
      StaticJsonDocument<256> responseDoc;
      responseDoc["token"] = token;
  
      JsonObject userObj = responseDoc.createNestedObject("user");
      userObj["username"] = username;
      userObj["displayName"] = "Administrator";
  
      String jsonResponse;
      serializeJson(responseDoc, jsonResponse);
  
      //Serial.printf("Login success, token: %s\n", token.c_str());
      sendJsonResponse(request, 200, jsonResponse);
    } else {
      sendJsonResponse(request, 401, "{\"error\":\"Invalid credentials\"}");
    } });

  server.on("/api/logout", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
  { sendJsonResponse(request, 204, ""); });

  server.on("/api/logout", HTTP_POST, [](AsyncWebServerRequest *request)
            {
    Serial.printf("Received logout request\n");
    if (!isAuthenticated(request)) {
      sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
      return;
    }
  
    String token = getAuthToken(request);
    if (logoutUserByToken(token)) {
      sendJsonResponse(request, 200, "{\"message\":\"Logged out successfully\"}");
    } else {
      sendJsonResponse(request, 400, "{\"error\":\"Logout failed\"}");
    } });

  server.on("/api/sessions", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
    { sendJsonResponse(request, 204, ""); });
  
  server.on("/api/sessions", HTTP_GET, [](AsyncWebServerRequest *request)
            {
    if (!isAuthenticated(request)) {
      sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
      return;
    }
  
    String token = getAuthToken(request);
    String requester;
    if (!validateJWT(token, requester) || requester != "admin") {
      sendJsonResponse(request, 403, "{\"error\":\"Forbidden: Admin only\"}");
      return;
    }
  
    StaticJsonDocument<1024> doc;
    JsonArray arr = doc.createNestedArray("sessions");
  
    for (int i = 0; i < MAX_SESSIONS; i++) {
      if (sessions[i].token != "") {
        JsonObject obj = arr.createNestedObject();
        obj["username"] = sessions[i].username;
        obj["expiryMillis"] = sessions[i].expiryMillis;
      }
    }
  
    String json;
    serializeJson(doc, json);
    sendJsonResponse(request, 200, json); });

  server.on("/api/sessions", HTTP_DELETE, [](AsyncWebServerRequest *request)
            {
    if (!isAuthenticated(request)) {
      sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
      return;
    }
  
    String token = getAuthToken(request);
    String requester;
    if (!validateJWT(token, requester) || requester != "admin") {
      sendJsonResponse(request, 403, "{\"error\":\"Forbidden: Admin only\"}");
      return;
    }
  
    if (!request->hasParam("username")) {
      sendJsonResponse(request, 400, "{\"error\":\"Username parameter is required\"}");
      return;
    }
  
    String targetUser = request->getParam("username")->value();
    bool removed = false;
  
    for (int i = 0; i < MAX_SESSIONS; i++) {
      if (sessions[i].username == targetUser && sessions[i].token != "") {
        sessions[i].token = "";
        sessions[i].expiryMillis = 0;
        sessions[i].createdAtMillis = 0;
        sessions[i].username = "";
        removed = true;
      }
    }
  
    if (removed) {
      saveSessionsToFile();
      sendJsonResponse(request, 200, "{\"message\":\"Session(s) removed for user '" + targetUser + "'\"}");
    } else {
      sendJsonResponse(request, 404, "{\"error\":\"No sessions found for user\"}");
    } });

  server.on("/api/user", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
            { sendJsonResponse(request, 204, ""); });
  server.on("/api/user", HTTP_GET, [](AsyncWebServerRequest *request)
            { withAuth(request, [request](String username)
                       {
      String jsonResponse = "{\"user\":\"" + username + "\"}";
      sendJsonResponse(request, 200, jsonResponse); }); });

  server.on("/api/status/online", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
            { sendJsonResponse(request, 204, ""); });
  server.on("/api/status/online", HTTP_GET, [](AsyncWebServerRequest *request)
            {
    String jsonResponse =  "{\"status\":\"online\"}";
    sendJsonResponse(request, 200, jsonResponse); });

  /////////////////////////////////////////////////////////
  /**
   * DATABASE SYNC API
   * Endpoints to handle database sync operations
   */
  server.on("/api/sync/upload", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
            { sendJsonResponse(request, 204, ""); });
  // Upload database snapshot
  server.on("/api/sync/upload", HTTP_POST,
            // Request handler - will respond after file is processed
            [](AsyncWebServerRequest *request)
            {
              // Response is sent in the upload handler, not here
            },
            // Upload handler
            [](AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final)
            {
      static File dbFile;
      // Check authentication
      if (!isAuthenticated(request)) {
        sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
        return;
      }      
      // On first chunk, open the file for writing
      if (index == 0) {
        Serial.println("Starting database upload");
        dbFile = LittleFS.open(DATABASE_FILE, "w");
        if (!dbFile) {
          Serial.println("Failed to open file for writing");
          request->send(500, "application/json", "{\"success\":false,\"message\":\"Failed to save database file\"}");
          return;
        }
      }
      
      // Write this chunk of data
      if (dbFile && dbFile.write(data, len) != len) {
        Serial.println("Write failed");
        dbFile.close();
        request->send(500, "application/json", "{\"success\":false,\"message\":\"Write operation failed\"}");
        return;
      }
      
      // If this is the last chunk, close the file and respond
      if (final) {
        size_t totalSize = index + len;
        Serial.printf("Upload complete, %u bytes\n", totalSize);
        
        if (dbFile) {
          dbFile.close();
        }
        
        // Create JSON response
        DynamicJsonDocument doc(256);
        doc["success"] = true;
        doc["message"] = "Database uploaded successfully";
        
        // Format current timestamp (simplified version for ESP8266)
        char timestamp[25];
        unsigned long now = millis();
        sprintf(timestamp, "%010lu", now);
        doc["timestamp"] = timestamp;
        
        doc["size"] = totalSize;
        
        String response;
        serializeJson(doc, response);
        request->send(200, "application/json", response);
      }
    });

  // Get database snapshot info
  server.on("/api/sync/info", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
  { sendJsonResponse(request, 204, ""); });
  
  server.on("/api/sync/info", HTTP_GET, [](AsyncWebServerRequest *request)
  {
    // Check authentication
    if (!isAuthenticated(request)) {
      sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
      return;
    }              
    // Check if database file exists
    if (!LittleFS.exists(DATABASE_FILE)) {
      request->send(404, "application/json", "{\"success\":false,\"message\":\"No database file found\"}");
      return;
    }
    
    File file = LittleFS.open(DATABASE_FILE, "r");
    if (!file) {
      request->send(500, "application/json", "{\"success\":false,\"message\":\"Failed to open database file\"}");
      return;
    }
    
    // Get file size
    size_t fileSize = file.size();
    
    // Calculate hash
    // For large files, we'd need to process in chunks, but for simplicity:
    uint8_t* buffer = new uint8_t[fileSize];
    if (!buffer) {
      file.close();
      request->send(500, "application/json", "{\"success\":false,\"message\":\"Memory allocation failed\"}");
      return;
    }
    
    // Read the entire file
    file.read(buffer, fileSize);
    file.close();
    
    // Generate hash
    String hash = generateDatabaseHash(buffer, fileSize);
    delete[] buffer;
    
    // Create JSON response
    DynamicJsonDocument doc(512);
    doc["success"] = true;
    doc["fileExists"] = true;
    
    // ESP8266 doesn't have file modification time, so use uptime
    //char lastModified[25];
    time_t currentTime = time(nullptr);
    char timeStr[30];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%dT%H:%M:%SZ", gmtime(&currentTime));
    //sprintf(lastModified, "%010lu", now);
    doc["lastModified"] = timeStr;
    
    doc["size"] = fileSize;
    doc["hash"] = hash;
    
    String response;
    serializeJson(doc, response);
    request->send(200, "application/json", response); 
  });

  // Download database snapshot
  server.on("/api/sync/download", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
  { sendJsonResponse(request, 204, ""); });
  
  server.on("/api/sync/download", HTTP_GET, [](AsyncWebServerRequest *request)
            {
    // Check authentication
    if (!isAuthenticated(request)) {
      sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
      return;
    }
    // Check if database file exists
    if (!LittleFS.exists(DATABASE_FILE)) {
      request->send(404, "application/json", "{\"success\":false,\"message\":\"No database file found\"}");
      return;
    }
    
    // Use AsyncWebServerResponse to send the file
    request->send(LittleFS, DATABASE_FILE, "application/octet-stream", false); });

  /*
    Save & Load User Preferences
  */
  // OPTIONS handler for CORS preflight requests
  server.on("/api/preferences", HTTP_OPTIONS, [](AsyncWebServerRequest *request)
            { sendJsonResponse(request, 204, ""); });

  // POST endpoint to save preferences
  server.on("/api/preferences", HTTP_POST, [](AsyncWebServerRequest *request)
            { collectedData = ""; }, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total)
            {  
    // Check authentication
    if (!isAuthenticated(request)) {
      sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
      return;
    }
    // Append incoming data
    collectedData += String((char*)data).substring(0, len);
      // If this is the last chunk, process the complete data
  if (index + len >= total) {
    Serial.println("Complete preferences data: " + collectedData);    

    // Save to file
    File file = LittleFS.open(PREFERENCES_FILE, "w");
    if (!file) {
      Serial.println("Failed to open preferences file for writing");
      sendJsonResponse(request, 500, "{\"success\":false,\"message\":\"Failed to save preferences\"}");
      return;
    }

    size_t bytesWritten = file.print(collectedData);
    file.close();

    if (bytesWritten == 0) {
      Serial.println("Failed to write preferences to file");
      sendJsonResponse(request, 500, "{\"success\":false,\"message\":\"Failed to save preferences\"}");
      return;
    }

    char timestamp[25];
    unsigned long currentTime = millis();
    sprintf(timestamp, "%lu", currentTime);
    
    String jsonResponse = "{\"success\":true,\"message\":\"Preferences saved successfully\",\"timestamp\":\"" + String(timestamp) + "\"}";
    sendJsonResponse(request, 200, jsonResponse); 
    collectedData="";
    }
  });

  // GET endpoint to retrieve preferences
  server.on("/api/preferences", HTTP_GET, [](AsyncWebServerRequest *request)
  {    
    // Check authentication
    if (!isAuthenticated(request)) {
      sendJsonResponse(request, 401, "{\"error\":\"Unauthorized\"}");
      return;
    }

    // Check if preferences file exists
    if (!LittleFS.exists(PREFERENCES_FILE)) {
      String jsonResponse = "{\"success\":true,\"preferences\":null,\"message\":\"No saved preferences found\"}";
      sendJsonResponse(request, 200, jsonResponse);
      return;
    }

    // Read the file
    File file = LittleFS.open(PREFERENCES_FILE, "r");
    if (!file) {
      Serial.println("Failed to open preferences file for reading");
      sendJsonResponse(request, 500, "{\"success\":false,\"message\":\"Failed to load preferences\"}");
      return;
    }

    // Read file contents
    String fileContent = "";
    while (file.available()) {
      fileContent += (char)file.read();
    }
    file.close();

    // Create response with timestamp
    char timestamp[25]; // Buffer for timestamp string
    unsigned long currentTime = millis();
    sprintf(timestamp, "%lu", currentTime);
    
    // Construct the response JSON
    // We need to be careful with the JSON structure here
    // The preferences are already in JSON format, so we need to embed them properly
    String jsonResponse = "{\"success\":true,\"preferences\":" + fileContent + ",\"timestamp\":\"" + String(timestamp) + "\"}";
    sendJsonResponse(request, 200, jsonResponse); 
  });

  // Add this before server.begin()
  server.onRequestBody([](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
    // This relaxes header parsing
    request->addInterestingHeader("X-Client-Time"); 
  });


  
  server.on("/api/deletedb", HTTP_GET, [](AsyncWebServerRequest *request)
  { 
    LittleFS.remove(DATABASE_FILE);   
    String jsonResponse;
    if (!LittleFS.exists(DATABASE_FILE)) {
      jsonResponse = "{\"success\":true}";
    }else
      jsonResponse = "{\"success\":false}";

    sendJsonResponse(request, 200, jsonResponse);
    return;
  });

  
  // Handle all other requests (static files and 404)
  server.onNotFound([](AsyncWebServerRequest *request)
  {
    String path = request->url();
    Serial.println("onNotFound: Request for: " + path); 
    if (path.startsWith("/api/")) {
      String jsonResponse = "{\"error\":\"API endpoint not found\"}";
      sendJsonResponse(request, 404, jsonResponse);
      return;
    }
    // بقیه‌ی مسیرها مثل فایل‌ها رو از LittleFS سرو کن
    if (path == "/" || path == "") {
      path = sysCredentials.isDeviceConfig ? "/index.html" : "/config.html";
    } else if (path.startsWith("/")) {
      path = path.substring(1);
    }
  
    if (LittleFS.exists(path)) {
      File file = LittleFS.open(path, "r");
      if (file) {
        const char* mimeType;
        bool isGzip = false;
  
        if (path.endsWith(".css.gz")) {
          mimeType = "text/css";
          isGzip = true;
        } else if (path.endsWith(".js.gz")) {
          mimeType = "application/javascript";
          isGzip = true;
        } else {
          mimeType = getMimeType(path);
          isGzip = path.endsWith(".gz");
        }
  
        AsyncWebServerResponse *response = request->beginResponse(LittleFS, path, mimeType);
        if (isGzip) {
          response->addHeader("Content-Encoding", "gzip");
          Serial.println("Serving GZIP file: " + path);
        } else {
          Serial.println("Serving file: " + path);
        }
  
        request->send(response);
        file.close();
        return;
      }
    }
  
    // اگر فایل وجود نداشت هم همون رفتار بالا انجام بشه
    request->send(LittleFS, "/index.html", "text/html"); });

  server.begin();
}
void setup()
{
  char retry_to_connect_wifi = 0;

  Serial.begin(115200);

  systemLog("Starting ESP8266 Web Server v1.0.0");
  systemLog("Chip ID: %08X", ESP.getChipId());
  systemLog("Flash size: %u bytes", ESP.getFlashChipRealSize());

  // setupWatchdog();
  setupFileSystem();
  if (!loadSystemCredentials())
  {
    systemLog("Load System Credentials failed!");
  }
  systemLog(sysCredentials.DeviceName.c_str());
  systemLog(sysCredentials.apSSID.c_str());
  systemLog(sysCredentials.apPassword.c_str());

  WiFi.hostname(sysCredentials.DeviceName);
  WiFi.begin(sysCredentials.apSSID, sysCredentials.apPassword);
  Serial.print("Connecting to WiFi .");
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(1000);
    Serial.print(".");
    retry_to_connect_wifi++;
    if (retry_to_connect_wifi > 20)
    {
      retry_to_connect_wifi = 0;
    }
  }
  Serial.print("\nConnected to WiFi with IP: ");
  Serial.println(WiFi.localIP());

  size_t wifiTaskId = scheduler.addTask(
      []()
      {
        if (WiFi.status() != WL_CONNECTED)
        {
          systemLog("Wifi Disconnected!");
        }
        else
          systemLog("Wifi Connected!");
      },
      5000,  // Interval ms
      true,  // Enabled
      false, // RunOnce
      "wifi" // Task name
  );
  /*
    // Example of working with tasks by index
    Serial.printf("Time until blink task runs: %d ms\n",
      scheduler.getTaskTimeRemaining(blinkTaskId));

    // Example of finding a task by name
    int counterTaskIndex = scheduler.findTaskByName("counter");
    if (counterTaskIndex >= 0) {
      Serial.printf("Found counter task at index %d\n", counterTaskIndex);
    }
  */
  if (loadSessionsFromFile())
  {
    // removeExpiredSessions(); // remove expired sessions periodically after restart
    Serial.println("Active sessions restored.");
  }

  setupWebServer();
}

void loop()
{
  static unsigned long lastMemCheck = 0;
  if (millis() - lastMemCheck > 15000)
  {
    Serial.printf("Free heap: %u bytes\n", ESP.getFreeHeap());
    lastMemCheck = millis();
  }
  // Execute all scheduled tasks
  scheduler.execute();
  // Reset watchdog to indicate the main loop is running
  resetWatchdog();
  // Yield to the system to handle WiFi and other background tasks
  yield();
}