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
import {lang} from './@arkts.lang';
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

@Sendable
class SendableClassA<T> {
    var1: number = 1;
    var2: string = '1';
}

@Sendable
class SendableClassB {
    var1: number = 1;
    var2: string = '1';
}

class NoneSendableClassA {
  var1: number = 1;
  var2: string = '1';
}

let ObjectA1: SendableClassA<SendableClassB> = new SendableClassA<SendableClassB>(); // OK
let ObjectA2: SendableClassA<number> = new SendableClassA<number>(); // OK
let ObjectA3: SendableClassA<string> = new SendableClassA<string>(); // OK
let ObjectA4: SendableClassA<boolean> = new SendableClassA<boolean>(); // OK
let ObjectA5: SendableClassA<bigint> = new SendableClassA<bigint>(); // OK
let ObjectA6: SendableClassA<null> = new SendableClassA<null>(); // OK
let ObjectA7: SendableClassA<undefined> = new SendableClassA<undefined>(); // OK

let NoneSendableObjectA1: SendableClassA<NoneSendableClassA> = new SendableClassA<NoneSendableClassA>(); // error

namespace collections {
  @Sendable
  export class Array<T> {
      constructor(){};
  }

  @Sendable
  export class Map<K, V> {
      constructor(){};
  }
}

let arr1: collections.Array<NoneSendableClassA> = new collections.Array<NoneSendableClassA>(); // error
let arr2: collections.Array<NoneSendableClassA> = new collections.Array(); // error
let arr3: collections.Array<NoneSendableClassA> = new collections.Array<SendableClassB>(); //error
let arr4: collections.Array<SendableClassB> = new collections.Array<SendableClassB>();
let arr5: collections.Array<SendableClassB> = new collections.Array();

let map1: collections.Map<string,NoneSendableClassA> = new collections.Map<string,NoneSendableClassA>(); // error
let map2: collections.Map<string,NoneSendableClassA> = new collections.Map(); // error
let map3: collections.Map<string,NoneSendableClassA> = new collections.Map<string,SendableClassB>(); // error
let map4: collections.Map<string,SendableClassB> = new collections.Map<string,SendableClassB>();
let map5: collections.Map<string,SendableClassB> = new collections.Map();

interface SI<T> extends lang.ISendable {
  var1: number;
  var2: string;
}

@Sendable
class SendableClassC implements SI<SendableClassB> {
    var1: number = 1;
    var2: string = '1';
}

let ObjectC1: SI<NoneSendableClassA> = new SendableClassC(); // ERROR

interface NSI<T> {
  var1: number;
  var2: string;
}

class NoneSendableClassC implements NSI<NoneSendableClassA> {
  var1: number = 1;
  var2: string = '1';
}

let ObjectC2: NSI<NoneSendableClassA> = new NoneSendableClassC();