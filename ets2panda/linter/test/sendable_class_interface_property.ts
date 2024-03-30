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

import {lang} from './@arkts.lang';

class NonSendableClass2 {}

@Sendable
class SendableClass10 {}

@Sendable
class SendableClass4<T, U> {
  prop1: number; // OK
  prop2: string; // OK
  prop3: boolean; // OK
  prop4: bigint; // OK
  prop5: SendableClass3; // OK
  prop6: null; // OK
  prop7: undefined; // OK
  prop8: U; // OK
  prop9: T | number | undefined; // OK
  prop10: alias0; // OK
  prop11: alias1; // OK
  prop12: ISendableExt1; // OK
  prop13: ConstEnum; // OK
  prop14: ConstEnum1; // OK
  prop15: ConstEnum2; // OK
  prop16: ConstEnum2 = ConstEnum2.Memc2; // OK
}

@Sendable
class SendableClass3 {
  prop1: string[]; // ERROR, sendable class property cannot be array
  prop2: NonSendableClass2; // ERROR, sendable class property cannot be non-sendable-class
  prop3: NonSendableClass2 | null; // ERROR, sendable class property cannot be non-sendable-class union type
  prop4: NonSendableInterface | number; // ERROR, sendable class property cannot be non-sendable-class union type
  prop5: NonSendableClass2 | null | undefined; // ERROR, sendable class property cannot be non-sendable-class union type
  prop6: alias2; // ERROR, sendable class property cannot be non-sendable-type
  prop7: alias3; // ERROR, sendable class property cannot be non-sendable-type
  prop8: RegularEnum; // ERROR, sendable class property cannot be non-sendable-type
  prop9: RegularEnum1; // ERROR, sendable class property cannot be non-sendable-type
  prop10: RegularEnum2; // ERROR, sendable class property cannot be non-sendable-type
  prop11: RegularEnum2 = RegularEnum2.Memr3; // ERROR, sendable class property cannot be non-sendable-type
  ["aaa"]: number; // ERROR, sendable class property name cannot be computed property
}

type alias0 = number | null;
type alias1 = SendableClass10;
type alias2 = NonSendableClass2;
type alias3 = NonSendableClass2 | undefined;

const enum ConstEnum {};
const enum ConstEnum1 {
  Memc1 = 1
};
const enum ConstEnum2 {
  Memc2 = 'aa',
  Memc3 = 2
};

enum RegularEnum {};
enum RegularEnum1 {
  Memr1 = 'aa'
};
enum RegularEnum2 {
  Memr2 = 'aa',
  Memr3 = 2
};

// Implement interface extending ISendable
interface ISendableExt1 extends lang.ISendable {
  prop1: number; // OK
  prop2: string; // OK
  prop3: boolean; // OK
  prop4: bigint; // OK
  prop5: SendableClass3; // OK
  prop6: null; // OK
  prop7: undefined; // OK
  prop8: SendableClass3 | string; // OK
  prop9: number | null | undefined; // OK
  prop10: alias0; // OK
  prop11: alias1; // OK
  prop12: ISendableExt2; // OK
  prop13: ConstEnum; // OK
  prop14: ConstEnum1; // OK
  prop15: ConstEnum2; // OK
}
// Implement interface extending ISendable
interface ISendableExt2 extends lang.ISendable {
  prop1: string[]; // ERROR, sendable interface property cannot be array
  prop2: NonSendableClass2; // ERROR, sendable interface property cannot be non-sendable-class
  prop3: NonSendableClass2 | null; // ERROR, sendable interface property cannot be non-sendable-class union type
  prop4: NonSendableInterface | string; // ERROR, sendable interface property cannot be non-sendable-class union type
  prop5: NonSendableClass2 | null | undefined; // ERROR, sendable interface property cannot be non-sendable-class union type
  prop6: alias2; // ERROR, sendable interface property cannot be non-sendable-type
  prop7: alias3; // ERROR, sendable interface property cannot be non-sendable-type
  prop8: RegularEnum; // ERROR, sendable interface property cannot be non-sendable-type
  prop9: RegularEnum1; // ERROR, sendable interface property cannot be non-sendable-type
  prop10: RegularEnum2; // ERROR, sendable interface property cannot be non-sendable-type
  ["aaa"]: number; // ERROR, sendable interface property name cannot be computed property
}

interface NonSendableInterface {};