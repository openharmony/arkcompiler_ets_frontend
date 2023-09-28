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

package com.ohos.migrator.test.kotlin;

public fun main() {
    // Integer
    val integer = 50;
    val integer2 = 1_2_3_4;
    val longVal = 100L;
    val longVal2 = 50_60_70L;
    val hex = 0x5A;
    val hex2 = 0X1_B_C;
    val binary = 0b10;
    val binary2 = 0B01_01_101;

    // Floating-point
    val floatVal = 1f;
    val floatVal2 = 2_3.4_5F;
    val floatVal3 = 10e2_0f;
    val floatVal4 = 45E+3F;

    val doubleVal = 1.25;
    val doubleVal2 = 2.5E-10;
    val doubleVal3 = .45_67;
    val doubleVal4 = 3e+5;

    // Boolean
    val trueVal = true;
    val falseVal = false;

    // Character
    val letter = 'a';
    val digit = '5';
    val cr = '\r';
    val lf = '\n';
    val tab = '\t';
    val backspace = '\b';
    val quote = '\'';
    val doubleQuote = '\"';
    val backslash = '\b';
    val dollar = '\$';
    val unicode = '\u01FA'

    // Null
    val nullVal = null
}