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
  prop17: ConstEnum | ConstEnum1 | ConstEnum2; // OK
  prop18: ConstEnum | SendableClass3; // OK
  prop19: ConstEnum1 | SendableClass10; // OK
  prop20: N.ConstEnum | ConstEnum; // OK
  prop21: alias4; // OK
  prop22: alias5; // OK
  prop23: alias6; // OK
  prop24: SendableClass3 | alias4 | alias5; // OK
  prop25: number | boolean; // OK
  prop26: boolean | bigint; // OK
  prop27: boolean | null; // OK
  prop28: bigint | null; // OK
  prop29: alias14; // OK
  prop30: alias15; // OK
  prop31: (number);
  prop32: (boolean | bigint);
  prop33: number | (SendableClass3 | ((null | string)));
  prop34: alias16;
  prop35: alias17;
  prop36: alias18;
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
  prop12: ConstEnum1.Memc1; // ERROR, sendable class property cannot be enum member type
  prop13: ConstEnum2.Memc2; // ERROR, sendable class property cannot be enum member type
  prop14: ConstEnum | ConstEnum1.Memc1; // ERROR, sendable class property cannot be non-sendable union type
  prop15: ConstEnum2 | RegularEnum1; // ERROR, sendable class property cannot be non-sendable union type
  prop16: RegularEnum2.Memr2 | SendableClass10; // ERROR, sendable class property cannot be non-sendable union type
  prop17: alias7; // ERROR, sendable class property cannot be non-sendable alias type
  prop18: alias8; // ERROR, sendable class property cannot be non-sendable alias type
  prop19: alias9; // ERROR, sendable class property cannot be non-sendable alias type
  prop20: alias6 | NonSendableInterface; // ERROR, sendable class property cannot be non-sendable union type
  prop21: alias7 | SendableClass3; // ERROR, sendable class property cannot be non-sendable union type
  prop22: SendableClass10 | alias8; // ERROR, sendable class property cannot be non-sendable union type
  prop23: 1; // ERROR, sendable class property cannot be numeric literal type
  prop24: 'x'; // ERROR, sendable class property cannot be string literal type
  prop25: true; // ERROR, sendable class property cannot be boolean literal type
  prop26: 2n; // ERROR, sendable class property cannot be bigint literal type
  prop27: true | false; // ERROR, sendable class property cannot be non-sendable union type
  prop271: 3 | 'y' | false | 4; // ERROR, sendable class property cannot be non-sendable union type
  prop28: SendableClass3 | 5; // ERROR, sendable class property cannot be non-sendable union type
  prop29: alias10; // ERROR, sendable class property cannot be non-sendable alias type
  prop30: alias11; // ERROR, sendable class property cannot be non-sendable alias type
  prop31: alias12; // ERROR, sendable class property cannot be non-sendable alias type
  prop32: alias13; // ERROR, sendable class property cannot be non-sendable alias type
  prop33: (10);
  prop34: (true | 'false');
  prop35: number | (SendableClass3 | ((string | NonSendableClass2)));
  prop36: alias19;
  prop37: alias20;
  ["aaa"]: number; // ERROR, sendable class property name cannot be computed property 
}

type alias0 = number | null;
type alias1 = SendableClass10;
type alias2 = NonSendableClass2;
type alias3 = NonSendableClass2 | undefined;
type alias4 = ConstEnum;
type alias5 = ConstEnum1 | ConstEnum2;
type alias6 = ConstEnum | SendableClass3;
type alias7 = RegularEnum | RegularEnum1 | ConstEnum;
type alias8 = ConstEnum1.Memc1;
type alias9 = ConstEnum | ConstEnum2.Memc3;
type alias10 = 10;
type alias11 = 'foo';
type alias12 = 20 | 'bar';
type alias13 = true | false;
type alias14 = number | boolean;
type alias15 = boolean | null | undefined;
type alias16 = (number);
type alias17 = (boolean | null);
type alias18 = (SendableClass3 | string);
type alias19 = number | (string | ((SendableClass3 | NonSendableClass2)));
type alias20 = (1 | '2' | true);

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

export declare namespace N {
  export const enum ConstEnum {
    E1 = 1
  }
}

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
  [Symbol.iterator](): IterableIterator<number>;
}

interface NonSendableInterface {};
