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

class NonSendableClass4 {}

@Sendable
class SendableClass6 {}

let v0 = new SendableClass6() as NonSendableClass4; // OK

let v1 = new NonSendableClass4() as SendableClass6; // ERROR, non-sendable data can not be cast to "Sendable" data

let tmp1 = new NonSendableClass4();

let v2 = tmp1 as SendableClass6; // ERROR, non-sendable data can not be cast to "Sendable" data

function foo(a: object) {
  a as SendableClass6; // OK
}

function foo(a: Object) {
  a as SendableClass6; // OK
}

function foo(a: any) {
  a as SendableClass6; // OK, no arkts-sendable-as-expr error
}
