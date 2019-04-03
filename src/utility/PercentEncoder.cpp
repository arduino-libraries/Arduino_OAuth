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

#include "PercentEncoder.h"

PercentEncoderClass::PercentEncoderClass()
{
}

String PercentEncoderClass::encode(const char* str)
{
  return encode(str, strlen(str));
}

String PercentEncoderClass::encode(const String& str)
{
  return encode(str.c_str(), str.length());
}

String PercentEncoderClass::encode(const char* str, int length)
{
  String encoded;

  encoded.reserve(length);

  for (int i = 0; i < length; i++) {
    char c = str[i];

    const char HEX_DIGIT_MAPPER[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    if (isAlphaNumeric(c) || (c == '-') || (c == '.') || (c == '_') || (c == '~')) {
      encoded += c;
    } else {
      char s[4];

      s[0] = '%';
      s[1] = HEX_DIGIT_MAPPER[(c >> 4) & 0xf];
      s[2] = HEX_DIGIT_MAPPER[(c & 0x0f)];
      s[3] = 0;

      encoded += s;
    }
  }

  return encoded;
}

PercentEncoderClass PercentEncoder;
