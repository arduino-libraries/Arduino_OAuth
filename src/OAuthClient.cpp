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

  const char* queryParams = NULL;
  const char* bodyParams = NULL;

  // split the path from query params if necessary
  char* questionMark = strchr(path, '?');
  if (questionMark != NULL) {
    queryParams = (questionMark + 1);

    const char* temp = path;

    while (temp != questionMark) {
      url += *temp++;
    }
  } else {
    url += path;
  }

  if (strcmp(contentType, "application/x-www-form-urlencoded") == 0) {
    // only use the body as params if the body is URL encoded
    bodyParams = body;
  }

  unsigned long time = 0;

  if (_onGetTimeCallback) {
    time = _onGetTimeCallback();
  }

  String signature = calculateSignature(method, url.c_str(), time, queryParams, bodyParams);
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

static int strcmp_pointer(const void* a, const void* b) {
  return strcmp(*(const char**)a, *(const char**)b);
}

String OAuthClient::calculateSignature(const char* method, const char* url, unsigned long time, const char* queryParams, const char* bodyParams)
{
  // This function is long due to the complexity of the OAuth signature.
  // It must collect all the parameters from the oauth, query, and body params,
  // then sort the param key values lexographically. After these steps the 
  // signature can be calculated.

  // calculate the OAuth params
  String oauthParams;

  oauthParams += "oauth_consumer_key=";
  oauthParams += _consumerKey;
  oauthParams += "&oauth_nonce=";
  oauthParams += _nonce;
  oauthParams += "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=";
  oauthParams += String(time);
  oauthParams += "&oauth_token=";
  oauthParams += _accessToken;
  oauthParams += "&oauth_version=1.0";

  // calculate the length of all of the params
  int paramsLength = oauthParams.length();
  int queryParamsLength = strlen(queryParams);
  int bodyParamsLength = strlen(bodyParams);

  if (queryParams) {
    paramsLength += (1 + queryParamsLength);
  }

  if (bodyParams) {
    paramsLength += (1 + bodyParamsLength);
  }

  // copy the parameters to a buffer
  char params[paramsLength + 1];
  char* temp = params;

  temp = strcpy(temp, oauthParams.c_str());
  temp += oauthParams.length();

  if (queryParams) {
    *temp++ = '&';
    strcpy(temp, queryParams);
    temp += queryParamsLength;
  }

  if (bodyParams) {
    *temp++ = '&';
    strcpy(temp, bodyParams);
    temp += bodyParamsLength;
  }

  *temp = '\0';

  // caculate the number of parameters
  int numParams = 0;
  for (int i = 0; i < paramsLength; i++) {
    if (params[i] == '=') {
      numParams++;
    }
  }

  // collect the keys of the parameters to an array
  // and also replace the = and & characters with \0
  // this will help with the sorting later
  const char* paramKeys[numParams];
  int paramIndex = 0;
  const char* lastKey = params;

  temp = params;
  while (1) {
    char c = *temp;

    if (c == '\0') {
      break;
    } else if (c == '=') {
      paramKeys[paramIndex++] = lastKey;

       *temp = '\0';
    } else if (c == '&') {
      lastKey = (temp + 1);

       *temp = '\0';
    }

    temp++;
  }

  // sort the param keys
  qsort(paramKeys, numParams, sizeof(uintptr_t), strcmp_pointer);

  // calculate the signature
  SHA1.beginHmac(_signingKey);
  SHA1.print(method);
  SHA1.print("&");
  SHA1.print(URLEncoder.encode(url));
  SHA1.print("&");
  for (int i = 0; i < numParams; i++) {
    const char* paramKey = paramKeys[i];
    int keyLength = strlen(paramKey);
    const char* paramValue = paramKey + keyLength + 1;

    SHA1.print(URLEncoder.encode(paramKey));
    SHA1.print(URLEncoder.encode("="));
    SHA1.print(URLEncoder.encode(paramValue));

    if ((i + 1) < numParams) {
      SHA1.print(URLEncoder.encode("&"));
    }
  }
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

  return URLEncoder.encode(signature);
}

String OAuthClient::calculateOauthAuthorization(const String& signature, unsigned long timestamp) {
  String authorization;

  authorization += "OAuth ";
  authorization += "oauth_consumer_key=\"";
  authorization += _consumerKey;
  authorization += "\",oauth_nonce=\"";
  authorization += _nonce;
  authorization += "\",oauth_signature=\"";
  authorization += signature;
  authorization += "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"";
  authorization += timestamp;
  authorization += "\",oauth_token=\"";
  authorization += _accessToken;
  authorization += "\",oauth_version=\"1.0\"";

  return authorization;
}
