/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

// 1) All fields implemented — no error
interface I1 {
  a: number;
  b: string;
}
class C1 implements I1 { // ✅ no error
  a: number = 0.0;
  b: string = '';
}

// 2) One field missing — error
interface I2 {
  x: boolean;
  y: number;
  cb(): void;
}
class C2 implements I2 { // ❌ Error: missing `y`
  x: boolean = true;
}
class C21 implements I2 { // ❌ Error: missing `cb()`
  x: boolean = true;
  y: number = 5.0;
}

// 3) Optional fields are treated as required — error
interface I3 {
  foo?: string;
  bar?: number;
}
class C3 implements I3 { // ❌ Error: missing both `foo` and `bar` (first missing stops checking)
}

// 4) Optional field implemented
class C4 implements I3 { // ✅ no error
  foo?: string;
  bar?: number;
}

// 5) Interface extends another
interface A5 {
  p: string;
}
interface B5 extends A5 {
  q: string;
}
class C5 implements B5 { // ✅ no error
  p: string = 'hello';
  q: string = 'world';
}
class C6 implements B5 { // ❌ Error: missing `q`
  p: string = 'hello';
}
class C61 implements B5 { // ❌ Error: missing `p`
  q: string = 'hello';
}

// 6) Multiple interfaces at once
interface I6a { u: number }
interface I6b { v: boolean }
class C7 implements I6a, I6b { // ✅ no error
  u: number = 42.0;
  v: boolean = false;
}
class C8 implements I6a, I6b { // ❌ Error: missing `v`
  u: number = 42.0;
}
