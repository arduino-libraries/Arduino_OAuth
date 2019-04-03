/*
  This file is part of the Arduino OAuth library.
  Copyright (c) 2019 Arduino SA. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <ArduinoBearSSL.h>

#include "b64.h" // from ArduinoHttpClient
#include "utility/PercentEncoder.h"

#include "OAuthClient.h"

OAuthClient::OAuthClient(Client& client, const char* host, uint16_t port) :
  _httpClient(client, host, port),
  _host(host),
  _ip(0, 0, 0, 0),
  _port(port)
{
}

OAuthClient::OAuthClient(Client& client, const String& host, uint16_t port) :
  OAuthClient(client, host.c_str(), port)
{
}

OAuthClient::OAuthClient(Client& client, const IPAddress& ip, uint16_t port) :
  _httpClient(client, ip, port),
  _host(NULL),
  _ip(ip),
  _port(port)
{
}

OAuthClient::~OAuthClient()
{
}

void OAuthClient::setCredentials(const char* consumerKey, const char* consumerSecret, const char* accessToken, const char* accessTokenSecret)
{
  _consumerKey = consumerKey;
  _accessToken = accessToken;

  // signing key is "<consumer secret>&<access token secret"
  _signingKey.reserve(strlen(consumerSecret) + strlen(accessTokenSecret) + 1);

  _signingKey += consumerSecret;
  _signingKey += "&";
  _signingKey += accessTokenSecret;
}

void OAuthClient::setCredentials(const String& consumerKey, const String& consumerSecret, const String& accessToken, const String& accessTokenSecret)
{
  return setCredentials(consumerKey.c_str(), consumerSecret.c_str(), accessToken.c_str(), accessTokenSecret.c_str());
}

void OAuthClient::onGetTime(unsigned long(*callback)(void))
{
  _onGetTimeCallback = callback;
}

int OAuthClient::get(const char* path)
{
  return httpRequest(HTTP_METHOD_GET, path, NULL, NULL);
}

int OAuthClient::get(const String& path)
{
  return get(path.c_str());
}

int OAuthClient::post(const char* path)
{
  return httpRequest(HTTP_METHOD_POST, path, NULL, NULL);
}

int OAuthClient::post(const String& path)
{
  return post(path.c_str());
}

int OAuthClient::post(const char* path, const char* contentType, const char* body)
{
  return httpRequest(HTTP_METHOD_POST, path, contentType, body);
}

int OAuthClient::post(const String& path, const String& contentType, const String& body)
{
  return post(path.c_str(), contentType.c_str(), body.c_str());
}

int OAuthClient::put(const char* path)
{
  return httpRequest(HTTP_METHOD_PUT, path, NULL, NULL);
}

int OAuthClient::put(const String& path)
{
  return put(path.c_str());
}

int OAuthClient::put(const char* path, const char* contentType, const char* body)
{
  return httpRequest(HTTP_METHOD_PUT, path, contentType, body);
}

int OAuthClient::put(const String& path, const String& contentType, const String& body)
{
  return put(path.c_str(), contentType.c_str(), body.c_str());
}

int OAuthClient::patch(const char* path)
{
  return httpRequest(HTTP_METHOD_PATCH, path, NULL, NULL);
}

int OAuthClient::patch(const String& path)
{
    return patch(path.c_str());
}

int OAuthClient::patch(const char* path, const char* contentType, const char* body)
{
  return httpRequest(HTTP_METHOD_PATCH, path, contentType, body);
}

int OAuthClient::patch(const String& path, const String& contentType, const String& body)
{
  return patch(path.c_str(), contentType.c_str(), body.c_str());
}

int OAuthClient::del(const char* path)
{
  return httpRequest(HTTP_METHOD_DELETE, path, NULL, NULL);
}

int OAuthClient::del(const String& path)
{
  return del(path.c_str());
}

int OAuthClient::del(const char* path, const char* contentType, const char* body)
{
  return httpRequest(HTTP_METHOD_PATCH, path, contentType, body);
}

int OAuthClient::del(const String& path, const String& contentType, const String& body)
{
  return del(path.c_str(), contentType.c_str(), body.c_str());
}

int OAuthClient::responseStatusCode()
{
  return _httpClient.responseStatusCode();
}

String OAuthClient::responseBody()
{
  return _httpClient.responseBody();
}

int OAuthClient::httpRequest(const char* method, const char* path, const char* contentType, const char* body)
{
  _nonce = createNonce();

  String url;

  url += (_port == 443) ? "https" : "http";
  url += "://";
  if (_host) {
    url += _host;
  } else {
    url += _ip[0];
    url += '.';
    url += _ip[1];
    url += '.';
    url += _ip[2];
    url += '.';
    url += _ip[3];
  }

  url += path;

  unsigned long time = 0;

  if (_onGetTimeCallback) {
    time = _onGetTimeCallback();
  }

  String signature = calculateSignature(method, url.c_str(), time, body);
  String authorization = calculateOauthAuthorization(signature, time);

  _httpClient.beginRequest();
  int result = _httpClient.startRequest(path, method);
  
  if (contentType) {
    _httpClient.sendHeader("Content-Type", contentType);
  }

  if (body) {
    _httpClient.sendHeader("Content-Length", strlen(body));
  }

  _httpClient.sendHeader("Authorization", authorization);
  _httpClient.beginBody();
  _httpClient.print(body);
  _httpClient.endRequest();
  
  return result;
}

String OAuthClient::createNonce() {
  String n;

  n.reserve(32);
  
  while (n.length() < 32) {
    char c = random(255);

    if (isAlphaNumeric(c)) {
      n += c;
    }
  }

  return n;
}

String OAuthClient::calculateSignature(const char* method, const char* url, unsigned long time, const char* body)
{
  SHA1.beginHmac(_signingKey);
  SHA1.print(method);
  SHA1.print("&");
  SHA1.print(PercentEncoder.encode(url));
  SHA1.print("&");

  SHA1.print(PercentEncoder.encode("oauth_consumer_key="));
  SHA1.print(PercentEncoder.encode(_consumerKey));
  SHA1.print(PercentEncoder.encode("&"));
  SHA1.print(PercentEncoder.encode("oauth_nonce="));
  SHA1.print(PercentEncoder.encode(_nonce));
  SHA1.print(PercentEncoder.encode("&"));
  SHA1.print(PercentEncoder.encode("oauth_signature_method=HMAC-SHA1&"));
  SHA1.print(PercentEncoder.encode("oauth_timestamp="));
  SHA1.print(PercentEncoder.encode(String(time)));
  SHA1.print(PercentEncoder.encode("&"));
  SHA1.print(PercentEncoder.encode("oauth_token="));
  SHA1.print(PercentEncoder.encode(_accessToken));
  SHA1.print(PercentEncoder.encode("&"));
  SHA1.print(PercentEncoder.encode("oauth_version=1.0&"));
  SHA1.print(PercentEncoder.encode(body));
  SHA1.endHmac();

  int rawSignatureLength = SHA1.available();
  char rawSignature[rawSignatureLength];

  for (int i = 0; i < rawSignatureLength; i++) {
    rawSignature[i] = SHA1.read();
  }

  int signatureLength = (rawSignatureLength * 8) / 6;
  char signature[signatureLength + 1];
  signatureLength = b64_encode((const unsigned char*)rawSignature, rawSignatureLength,  (unsigned char*)signature, signatureLength);
  signature[signatureLength] = '\0';

  return PercentEncoder.encode(signature);
}

String OAuthClient::calculateOauthAuthorization(const String& signature, unsigned long timestamp) {
  String authorization;

  authorization += "OAuth ";
  authorization += "oauth_consumer_key=\"";
  authorization += _consumerKey;
  authorization += "\",";
  authorization += "oauth_nonce=\"";
  authorization += _nonce;
  authorization += "\",";
  authorization += "oauth_signature=\"";
  authorization += signature;
  authorization += "\",";
  authorization += "oauth_signature_method=\"HMAC-SHA1\",";
  authorization += "oauth_timestamp=\"";
  authorization += timestamp;
  authorization += "\",";
  authorization += "oauth_token=\"";
  authorization += _accessToken;
  authorization += "\",";
  authorization += "oauth_version=\"1.0\"";

  return authorization;
}
