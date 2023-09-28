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

package com.ohos.migrator.test.java;

class literals {
   void test() {
      // integer literals
      byte b = 0;
      byte b2 = 1_0_2;
      short s = 0x1;
      short s2 = 0X1_F;
      int i = 02;
      int i2 = 03_4_56;
      long l = 0b11L;
      long l2 = 0B1_01_11l;

      // floating-point literals
      float f = 4f;
      float f2 = 1_2.23_45e+6F;
      float f3 = 3.402_823_5e1_7f;
      double d = 5.;
      double d2 = .123_456;
      double d3 = 0.123876;
      double pi = 3.1416D;
      double G = 6.6_73_00E-11d;

      // char and string literals
      char c = '6';
      char c2 = '\t';
      char c3 = '\'';
      String str = "7";
      String str2 = "Who needs \"dots\" over \"eyes\"? ;)\r\n";

      // null and boolean literals
      literals nl = null;
      boolean tl = true;
      boolean fl = false;

      // class literals
      Class<literals> cl = literals.class;
      Class<?> ll = long.class;
      Class<String[]> sal = String[].class;
      Class<?> dal = double[].class;
   }
}
