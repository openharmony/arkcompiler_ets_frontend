/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

function fooAnd(x: String|null, y: String|null): string {
  if (x != null && y != null)  {
    return x + " " + y;
  } else if (x == null && y == null) {
    return "null";
  } else if (x != null && y == null) {
    return x;
  } else if (x == null && y != null) {
     return y;
  } else {
     throw new Error("Unreachable");
  }
}

function fooOr1(x: String|null, y: String|null): string {
  if (x != null || y != null)  {
    return "case 1";
  } else if (x == null && y == null) {
    return "null";
  } else {
     throw new Error("Unreachable");
  }
}

function fooOr2(x: String|null, y: String|null): string {
  if (x == null || y == null)  {
    return "case 1";
  } else if (x != null && y != null) {
    return x + " " + y;
  } else {
     throw new Error("Unreachable");
  }
}

function main(): void {
  assert(fooAnd("Test", "string") == "Test string");
  assert(fooAnd("Test", null) == "Test");
  assert(fooAnd(null, "string") == "string");
  assert(fooAnd(null, null) == "null");

  assert(fooOr1("Test", "string") == "case 1");
  assert(fooOr1("Test", null) == "case 1");
  assert(fooOr1(null, "string") == "case 1");
  assert(fooOr1(null, null) == "null");

  assert(fooOr2("Test", "string") == "Test string");
  assert(fooOr2("Test", null) == "case 1");
  assert(fooOr2(null, "string") == "case 1");
  assert(fooOr2(null, null) == "case 1");
}
