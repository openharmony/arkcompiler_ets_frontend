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

class NonSendableClass3 {}

@Sendable
class SendableClass3 {}

@Sendable
class SendableClass5<T, U> {
  prop1: T;
  prop2: U;
}

@Sendable
class SendableClass6<T=NonSendableClass3> { // ERROR, sendable class generic type cannot be non-sendable-class
  prop1: T;
}

@Sendable
class SendableClass7<T=SendableClass3> { // OK
  prop1: T;
}

let ins1 = new SendableClass5<number, string>; // OK
let ins2 = new SendableClass5<number, NonSendableClass3>; // ERROR, sendable class generic type cannot be non-sendable-class
let ins3 = new SendableClass5<number[], string[]>; // ERROR, sendable class generic type can only be sendable data type

let e = SendableClass5;
let b = e;

let c = Math.random()>0.5 ? SendableClass5 : NonSendableClass3;

let ins4 = new b<number, NonSendableClass3>; // ERROR, sendable class generic type cannot be non-sendable-class
let ins5 = new c<number, NonSendableClass3>; // OK, skip checker