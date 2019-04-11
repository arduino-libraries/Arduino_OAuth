/*
  Tweeter

  This sketch demonstrates how to post a Tweet directly to
  Twitter via the Twitter's HTTP API using OAuth 1.0 for authenticaion.

  OAuth credentials can be retrieved from the following
  website, using your Twitter account and creating a new
  app:

    https://developer.twitter.com/en/apps

  Circuit:
   - MKR WiFi 1010 board

  This example code is in the public domain.
*/

#include <ArduinoECCX08.h>     // ArduinoBearSSL depends on ArduinoECCX08
#include <ArduinoBearSSL.h>    // Arduino_OAuth depends on ArduinoBearSSL
#include <ArduinoHttpClient.h> // Arduino_OAuth depends on ArduinoHttpClient
#include <Arduino_OAuth.h>
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

void loop() {
  String status;

  // create the status text
  status += "millis() is now: ";
  status += millis();

  tweet(status);

  // wait one minute before Tweeting again
  delay(60 * 1000L);
}

unsigned long getTime() {
  // get the current time from the WiFi module
  return WiFi.getTime();
}

void tweet(String text) {
  Serial.println("Sending tweet: ");
  Serial.println(text);

  String requestBody;

  // build the URL encoded request body, the text must be URL encoded
  requestBody += "status=";
  requestBody += URLEncoder.encode(text);

  // HTTP POST it via the OAuth client, which sets the Authorization header for us
  oauthClient.post("/1.1/statuses/update.json", "application/x-www-form-urlencoded", requestBody);

  // read the HTTP status code and body
  int statusCode = oauthClient.responseStatusCode();
  String responseBody = oauthClient.responseBody();

  Serial.print("statusCode = ");
  Serial.println(statusCode);

  Serial.print("responseBody = ");
  Serial.println(responseBody);

  Serial.println();
}
