#ifndef TIME_SYNC_H
#define TIME_SYNC_H

#include <time.h>
#include <ArduinoJson.h>

// TimeSync class to handle client-provided time synchronization
class TimeSync {
  private:
      // Timestamp of last sync
      time_t lastSyncTime = 0;
      
      // Time offset (difference between ESP time and accurate time)
      int64_t timeOffset = 0;
      
      // Sync reliability score (0-100)
      uint8_t syncReliability = 0;
      
      // Minimum time between forced syncs (milliseconds)
      const unsigned long MIN_SYNC_INTERVAL = 60 * 60 * 1000; // 1 hour
      
      // Maximum allowed deviation in milliseconds
      const int64_t MAX_ALLOWED_DEVIATION = 10000; // 10 seconds
      
      // Counter for received timestamps
      uint32_t receivedTimestamps = 0;
      
      // Token bucket for throttling time updates
      struct {
          float tokens;
          float maxTokens;
          float tokenRate;
          unsigned long lastRefill;
      } updateThrottle = {5, 10, 0.1, 0}; // 0.1 tokens per second, max 10
  
  public:
      TimeSync() {
          // Initialize time with a default date/time
          configTime(0, 0, "pool.ntp.org"); // Set UTC time
          setenv("TZ", "UTC", 1);           // Set timezone to UTC
          
          // Initialize throttle
          updateThrottle.lastRefill = millis();
      }
      
      /**
       * Process a client timestamp and update internal time if needed
       * 
       * @param clientTimestamp Unix timestamp in seconds from client
       * @param requestLatency Estimated request latency in milliseconds (optional)
       * @return bool True if time was updated
       */
      bool processClientTime(time_t clientTimestamp, int requestLatency = 100) {
          // Refill token bucket
          unsigned long now = millis();
          unsigned long elapsed = now - updateThrottle.lastRefill;
          updateThrottle.lastRefill = now;
          
          updateThrottle.tokens += (elapsed / 1000.0) * updateThrottle.tokenRate;
          if (updateThrottle.tokens > updateThrottle.maxTokens) {
              updateThrottle.tokens = updateThrottle.maxTokens;
          }
          
          // Check if we can process this update
          if (updateThrottle.tokens < 1.0) {
              return false; // Not enough tokens
          }
          
          // Count received timestamps
          receivedTimestamps++;
          
          // Get current local time
          time_t currentTime = time(nullptr);
          
          // Calculate network latency compensation (half of the round trip)
          time_t adjustedClientTime = clientTimestamp + (requestLatency / 2000.0);
          
          // Calculate difference between client time and current time
          int64_t timeDiff = adjustedClientTime - currentTime;
          
          // Decide whether to update the time based on various factors
          bool shouldUpdate = false;
          
          // Always update if this is one of the first few timestamps
          if (receivedTimestamps <= 5) {
              shouldUpdate = true;
          }
          // Force update if it's been too long since last sync
          else if (lastSyncTime > 0 && (currentTime - lastSyncTime) > (MIN_SYNC_INTERVAL/1000)) {
              shouldUpdate = true;
          }
          // Update if the difference is significant but not extreme
          else if (abs(timeDiff) > 2 && abs(timeDiff) < 315360000) { // >2s but <10 years
              // Check if deviation exceeds our threshold
              if (abs(timeDiff) > MAX_ALLOWED_DEVIATION/1000) {
                  shouldUpdate = true;
              }
          }
          
          if (shouldUpdate) {
              // Use token
              updateThrottle.tokens -= 1.0;
              
              // Update the system time
              struct timeval tv;
              tv.tv_sec = adjustedClientTime;
              tv.tv_usec = 0;
              settimeofday(&tv, nullptr);
              
              // Update sync status
              lastSyncTime = adjustedClientTime;
              timeOffset = timeDiff;
              
              // Update reliability score
              if (receivedTimestamps <= 5) {
                  syncReliability = 20 * receivedTimestamps; // 20, 40, 60, 80, 100
              } else {
                  // Improve reliability for consistent updates
                  if (syncReliability < 100) {
                      syncReliability += 5;
                      if (syncReliability > 100) {
                          syncReliability = 100;
                      }
                  }
              }
              
              return true;
          }
          
          return false;
      }
      
      /**
       * Get current time as a formatted string
       */
      String getFormattedTime() {
          time_t now = time(nullptr);
          struct tm timeinfo;
          gmtime_r(&now, &timeinfo);
          
          char buffer[30];
          strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S UTC", &timeinfo);
          return String(buffer);
      }
      
      /**
       * Get current Unix timestamp
       */
      time_t getCurrentTimestamp() {
          return time(nullptr);
      }
      
      /**
       * Get time sync status as JSON
       */
      String getSyncStatus() {
          DynamicJsonDocument doc(256);
          doc["timestamp"] = getCurrentTimestamp();
          doc["formattedTime"] = getFormattedTime();
          doc["syncReliability"] = syncReliability;
          doc["lastSyncTime"] = lastSyncTime;
          doc["timeOffset"] = timeOffset;
          doc["receivedTimestamps"] = receivedTimestamps;
          
          String output;
          serializeJson(doc, output);
          return output;
      }
  };

  #endif