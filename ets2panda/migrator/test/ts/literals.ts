/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ 

function foo(): void {
    // Integer
    let integer = 50;
    let integer2 = 1_2_3_4;
    let hex = 0x5A;
    let hex2 = 0X1_B_C;
    let binary = 0b10;
    let binary2 = 0B01_01_101;
    let octal = 0o350;
    let octal2 = 0O125;
    let bigint = 145n;
    let bigint2 = 1_200_300_400_500_600_700_800_900_000_100_200_300_400_500_600n;

    // Floating-point
    let double1 = 1.;
    let double2 = .25;
    let double3 = 1.5;
    let double4 = .45_67;
    let double5 = 2_3.4_5;
    let double6 = 10e2_0;
    let double7 = 2.5E-10;
    let double8 = 3e+5; 
    let double9 = .45E2;

    // Boolean
    let bool1 = true;
    let bool2 = false;

    // Strings
    let singleQuotes = 'one line \n another line';
    let doubleQuotes = "foo 'bar' \"baz\"";
    let escapeQoutes = 'Apple \'Banana\' "Orange" \"Grape\" \\"Melon\\" \\\"Avocado\\\"';
    let escapeXmlSq = '& &amp; < &lt; > &gt; " &quot; \' &apos;';
    let escapeXmlDq = "& &amp; < &lt; > &gt; \" &quot; ' &apos;";
    // Escaped characters:
    let cr = '\r';
    let lf = '\n';
    let tab = '\t';
    let formFeed = '\f';
    let backspace = '\b';
    let verticalTab = '\v';
    let dollar = '\$';
    let nullByte = '\0';
    let quote = '\'';
    let doubleQuote = '\"';
    let backslash = '\\';
    let latin = '\251';
    let latin2 = '\xA9';
    let unicode = '\u01FA'
    let unicodeCodePointEsc = '\u{1D306}'

    // Null
    let nullLiteral = null;

    // Regular Expressions
    let re = /a(b+)c/;
    let re2 = /\w+\s/g;
    let re3 = /[.*+?^${}()|[\]\\]/g
    let re4 = /^(?:\d{3}|\(\d{3}\))([-/.])\d{3}\1\d{4}$/;
}