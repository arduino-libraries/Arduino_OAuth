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

#ifndef OAUTH_CLIENT_H_
#define OAUTH_CLIENT_H_

#include <ArduinoHttpClient.h>

class OAuthClient {
public:
  OAuthClient(Client& client, const char* host, uint16_t port = HttpClient::kHttpPort);
  OAuthClient(Client& client, const String& host, uint16_t port = HttpClient::kHttpPort);
  OAuthClient(Client& client, const IPAddress& ip, uint16_t port = HttpClient::kHttpPort);
  virtual ~OAuthClient();

  void setCredentials(const char* consumerKey, const char* consumerSecret, const char* accessToken, const char* accessTokenSecret);
  void setCredentials(const String& consumerKey, const String& consumerSecret, const String& accessToken, const String& accessTokenSecret);

  void onGetTime(unsigned long(*)(void));

  int get(const char* path);
  int get(const String& path);

  int post(const char* path);
  int post(const String& path);
  int post(const char* path, const char* contentType, const char* body);
  int post(const String& path, const String& contentType, const String& body);

  int put(const char* path);
  int put(const String& path);
  int put(const char* path, const char* contentType, const char* body);
  int put(const String& path, const String& contentType, const String& body);

  int patch(const char* path);
  int patch(const String& path);
  int patch(const char* path, const char* contentType, const char* body);
  int patch(const String& path, const String& contentType, const String& body);

  int del(const char* path);
  int del(const String& path);
  int del(const char* path, const char* contentType, const char* body);
  int del(const String& path, const String& contentType, const String& body);

  int responseStatusCode();
  String responseBody();

private:
  int httpRequest(const char* method, const char* path, const char* contentType, const char* body);

  String createNonce();
  String calculateSignature(const char* method, const char* url, unsigned long time, const char* queryParams, const char* bodyParams);
  String calculateOauthAuthorization(const String& signature, unsigned long timestamp);

private:
  HttpClient _httpClient;
  const char* _host;
  IPAddress _ip;
  int _port;

  String _consumerKey;
  String _accessToken;
  String _signingKey;

  unsigned long (*_onGetTimeCallback)(void);

  String _nonce;
};

#endif
