/*
  Get twitter status

  This example shows a REST API GET using OAuth 1.0
  authentication. It then parses the JSON response.

  OAuth credentials can be retrieved from your Twitter
  developer account after creating a new app:

    https://developer.twitter.com/en/apps

  Circuit:

   - Arduino MKR WiFi 1010 board

  This example code is in the public domain.
*/

#include <ArduinoECCX08.h>     // ArduinoBearSSL depends on ArduinoECCX08
#include <ArduinoBearSSL.h>    // Arduino_OAuth depends on ArduinoBearSSL
#include <ArduinoHttpClient.h> // Arduino_OAuth depends on ArduinoHttpClient
#include <Arduino_OAuth.h>
#include <Arduino_JSON.h>
#include <WiFiNINA.h>

#include "arduino_secrets.h"
///////please enter your sensitive data in the Secret tab/arduino_secrets.h
const char ssid[] = SECRET_SSID;    // your network SSID (name)
const char pass[] = SECRET_PASS;    // your network password (use for WPA, or use as key for WEP)

const char consumerKey[]       = SECRET_CONSUMER_KEY;
const char consumerKeySecret[] = SECRET_CONSUMER_KEY_SECRET;
const char accessToken[]       = SECRET_ACCESS_TOKEN;
const char accessTokenSecret[] = SECRET_ACCESS_TOKEN_SECRET;

int status = WL_IDLE_STATUS;     // the Wifi radio's status

WiFiSSLClient wifiSSLClient;
OAuthClient oauthClient(wifiSSLClient, "api.twitter.com", 443);

String twitterHandle = "arduino"; // Twitter handle to retrieve Tweets from

void setup() {
  //Initialize serial and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  // check for the WiFi module:
  if (WiFi.status() == WL_NO_MODULE) {
    Serial.println("Communication with WiFi module failed!");
    // don't continue
    while (true);
  }

  // attempt to connect to Wifi network:
  while (status != WL_CONNECTED) {
    Serial.print("Attempting to connect to WPA SSID: ");
    Serial.println(ssid);
    // Connect to WPA/WPA2 network:
    status = WiFi.begin(ssid, pass);

    // wait 10 seconds for connection:
    delay(10000);
  }

  // you're connected now
  Serial.println("You're connected to the network");
  Serial.println();

  Serial.print("Waiting for the network time to sync ");
  while (getTime() == 0) {
    Serial.print(".");
    delay(1000);
  }
  Serial.println();
  Serial.println();

  // assign the OAuth credentials
  oauthClient.setCredentials(consumerKey, consumerKeySecret, accessToken, accessTokenSecret);

  // assign the callback to get the current epoch time, the epoch time is
  // needed for every OAuth request, as it's used in the HTTP "Authorization"
  // request header value and to calculate the request's signature
  oauthClient.onGetTime(getTime);
}

unsigned long getTime() {
  // get the current time from the WiFi module
  return WiFi.getTime();
}

void loop() {
  // Twitter API requests latest Arduino status
  oauthClient.get("/1.1/statuses/user_timeline.json?screen_name=" + twitterHandle + "&count=1");

  int statusCode = oauthClient.responseStatusCode();
  String response = oauthClient.responseBody();

  if (statusCode != 200) {
    // An error occurred
    Serial.println(statusCode);
    Serial.println(response);
  } else {
    // Parse JSON response
    JSONVar statusesObject = JSON.parse(response);

    // print the handle
    Serial.print("@");
    Serial.print(twitterHandle);
    Serial.println("'s twitter status: ");

    // print the tweet text, retweet + favorite counts
    // we only care about the first item
    Serial.println(statusesObject[0]["text"]);
    Serial.print("Retweets: ");
    Serial.println(statusesObject[0]["retweet_count"]);
    Serial.print("Likes: ");
    Serial.println(statusesObject[0]["favorite_count"]);
  }
  Serial.println();

  // Wait one minute (see Twitter API rate limits before changing)
  delay(60 * 1000L);
}
