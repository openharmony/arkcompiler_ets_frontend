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

class nonSendableClass9 {}

@Sendable
class SendableClass9 {}

@Sendable
class SendableClass10<T> {
  prop1: number | null = {a: 1}; // OK
  prop2: string | bigint | null = [1, 2]; // OK
  prop3: SendableClass9 = {a: 1}; // ERROR, the initialization for "Sendable" objects is limited
  prop4: SendableClass9 = [1, 2]; // ERROR, the initialization for "Sendable" objects is limited
  prop5: SendableClass9 | T | BigInt = {a: 1}; // ERROR, the initialization for "Sendable" objects is limited
  prop6: SendableClass9 | T | BigInt  = [1, 2]; // ERROR, the initialization for "Sendable" objects is limited
}

let v0: string | nonSendableClass9 | undefined | null = {a: 1}; // OK
let v1: undefined | nonSendableClass9 | null = [1, 2]; // OK
let v2: SendableClass9 = {a: 1}; // ERROR, the initialization for "Sendable" objects is limited
let v3: SendableClass9 = [1, 2]; // ERROR, the initialization for "Sendable" objects is limited
let v4: SendableClass9 | nonSendableClass9 | BigInt = [1, 2]; // ERROR, the initialization for "Sendable" objects is limited
let v5: SendableClass9 | nonSendableClass9 | null = [1, 2]; // ERROR, the initialization for "Sendable" objects is limited