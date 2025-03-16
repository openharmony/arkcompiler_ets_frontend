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

import { 
  sendableClassA,
  sendableVar,
  nonSendableClassB,
  nonSendableVar,
  sendableInterface,
  nonSendableInterface,
  lang,
} from './@arkts.lang';

// sendable class
@Sendable
class localSendableClassA {}

// sendable class var
let localSendableVar = localSendableClassA


// non-sendable class
class localNonSendableClassB {}

// non-sendable class var
let localNonSendableVar = localNonSendableClassB

// sendable interface
interface localSendableInterface extends lang.ISendable {}

// non-sendable interface
interface localNonSendableInterface {}

// sendable interface type alias
type localSendableInterfaceAlias = localSendableInterface

// non-sendable interface type alias
type localNonSendableInterfaceAlias = localNonSendableInterface

// left: sendable class

// class + class

// case1: extends import var
// == case1.1: extends sendable
@Sendable
class sendableClass1 extends sendableVar {} // ERROR

// == case1.2: extends non-sendable
@Sendable
class sendableClass2 extends nonSendableVar {} // ERROR

// case2: extends local var
// == case2.1: extends sendable
@Sendable
class sendableClass3 extends localSendableVar {} // ERROR

// == case2.2: extends non-sendable
@Sendable
class sendableClass4 extends localNonSendableVar {} // ERROR

// case3: extends import class
// == case3.1: extends sendable
@Sendable
class sendableClass5 extends sendableClassA {} // OK

// == case3.2: extends non-sendable
@Sendable
class sendableClass6 extends nonSendableClassB {} // ERROR

// case4: extends local class
// == case4.1: extends sendable
@Sendable
class sendableClass7 extends localSendableClassA {} // OK

// == case4.2: extends non-sendable
@Sendable
class sendableClass8 extends localNonSendableClassB {} // ERROR

// class + interface

// case1: implements local interface
// == case1.1: implements sendable
@Sendable
class sendableClass9 implements localSendableInterface {} // OK

// == case1.2: implements non-sendable
@Sendable
class sendableClass10 implements localNonSendableInterface {} // OK

// case2: implements import interface
// == case2.1: implements sendable
@Sendable
class sendableClass11 implements sendableInterface {} // OK

// == case2.2: implements non-sendable
@Sendable
class sendableClass12 implements nonSendableInterface {} // OK

// case3: implements type alias
// == case3.1: implements sendable
@Sendable
class sendableClass13 implements localSendableInterfaceAlias {} // OK

// == case3.2: implements non-sendable
@Sendable
class sendableClass14 implements localNonSendableInterfaceAlias {} // OK

// left: non sendable class

// case1: extends import var
// == case1.1: extends sendable
class sendableClass15 extends sendableVar {} // ERROR

// == case1.2: extends non-sendable
class sendableClass16 extends nonSendableVar {} // OK

// case2: extends local var
// == case2.1: extends sendable
class sendableClass17 extends localSendableVar {} // ERROR

// == case2.2: extends non-sendable
class sendableClass18 extends localNonSendableVar {} // OK

// case3: extends import class
// == case3.1: extends sendable
class sendableClass19 extends sendableClassA {} // ERROR

// == case3.2: extends non-sendable
class sendableClass20 extends nonSendableClassB {} // OK

// case4: extends local class
// == case4.1: extends sendable
class sendableClass21 extends localSendableClassA {} // ERROR

// == case4.2: extends non-sendable
class sendableClass22 extends localNonSendableClassB {} // OK

// class + interface

// case1: implements local interface
// == case1.1: implements sendable
class sendableClass23 implements localSendableInterface {} // ERROR

// == case1.2: implements non-sendable
class sendableClass24 implements localNonSendableInterface {} // OK

// case2: implements import interface
// == case2.1: implements sendable
class sendableClass25 implements sendableInterface {} // ERROR

// == case2.2: implements non-sendable
class sendableClass26 implements nonSendableInterface {} // OK

// case3: implements type alias
// == case4.1: implements sendable
class sendableClass27 implements localSendableInterfaceAlias {} // ERROR

// == case4.2: implements non-sendable
class sendableClass28 implements localNonSendableInterfaceAlias {} // OK

// ISendable created by developer is not a sendable interface

interface ISendable {}

interface fakeSendableInterface extends ISendable {}

// fake sendable interface type alias
type fakeSendableInterfaceAlias = fakeSendableInterface

class sendableClass29 implements fakeSendableInterface {} // OK

class sendableClass30 implements fakeSendableInterfaceAlias {} // OK