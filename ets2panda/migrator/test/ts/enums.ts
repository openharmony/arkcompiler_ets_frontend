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

enum E {
   A = 1,
   B,
   C,
   D = 20,
   F = D*C,
   G = B+F,
   "H",
   "100\tI",
   100
}

const enum Constants {
   pi = 3.1415,
   e = 2.7182,
   h = 6.626e-34,
   au = 149597870700
}

enum Empty {
}

enum MyEnum {
   "100\tA",
   [foo()]
}

enum Computed {
   A,
   B = 20,
   C = bar(),
   D = 30,
   E,
   F = 40.4,
   G,
   H
}

enum Strings {
   SUCCESS = "OK",
   FAILURE = "Fail",
   GREETING = "Hello!",
}

enum Mixed {
   A = 1,
   B,
   C = "string",
   D = "another string",
   E = A + B,
   F,
   G = 200
}

function foo(): Symbol {
   return new Symbol("foo");

   enum Local {
      A,
      B = 100,
      C
   }

   enum Empty {
   }
}

function bar(): number {
   return 100;
}
