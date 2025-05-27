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

// TypeScript: treats 'n' as having type number
// ArkTS: treats 'n' as having type int to reach max code performance

import { Entry, Component, State, RelativeContainer, Text, AppStorage } from '@kit.ArkUI';

let a: number = 1;

a = 1; // OK
a = 1.5; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'

a += 1; // OK
a += 1.5; // ArkTS: Result is integer value

console.log(a + 1); // OK
console.log(a - 0.5); // OK
console.log(a / 2); // ArkTS: integer division is used, result is integer value
console.log(a / 2.5); // OK
console.log(2 / a); // ArkTS: integer division is used, result is integer value
console.log(2.5 / a); // OK

let b: number = 1;
a = b; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'
a += b; // ArkTS: Result is integer value
console.log(a + b); // OK
console.log(a / b); // OK

let c: number = 1.5;
a = c; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'
a += c; // ArkTS: Result is integer value
console.log(a + c); // OK
console.log(a / c); // OK

let d: number = 2;
a = d; // OK
a += d; // OK
console.log(a + d); // OK
console.log(a / d); // ArkTS: integer division is used, result is integer value

let n: number = 2;

let f: number = 1

let g: number[] = [1, 2, 3]

let x!: number

let t8: number = Infinity

let t9: number = -Infinity;

let t10: number = NaN;

let t11: number = Number.MAX_VALUE;

let t12: number = Number.MIN_VALUE;

let o:number = 123;

const oo:number = 123;

let o2: number = o; 

let o3: number = oo; 

class A{
   a: number = 1;
   constructor() {
  }
}

let t2: number = +123;

let t3: number = -234;

let num: number = Math.floor(4.8); // num 可能是 int

let value: number = parseInt("42"); // value 可能是 int


function multiply(x: number = 2, y: number = 3): number { 
 return x * y;
}

function divide(x: number, y: number): number {
  return x / y;
}

function identity<T>(value: T): T {
  return value;
}
identity<number>(42);

let an_array: number[] = [1, 2, 3]

let g: number = an_array[]

const a: number = 1

enum Test {
  A = 1,  // 显式赋值为 1
  B = 2   // 显式赋值为 2
}
const test: number = Test.A;

@Entry
@Component
struct Index2 {
  @State message: string = 'Hello World';
  readonly c1: number = 1; // int
  readonly c4: number = 1.7; // float
  readonly c5: number = 0x123; // 16进制
  readonly c6: number = 0o123; //8进制
  readonly c7: number = 0b101; //2进制
  readonly c8: number[] = [1, 2, 3];

build() {
    RelativeContainer() {
      Text(this.message)
        .onClick(() => {
        })
    }
  }
}

const c1: number = 1;

export class G{
  readonly a5: number = 4;
}

const fingerprintPositionY: number = AppStorage.get<number>(FingerprintConstants.COORDINATE_Y_OF_FINGERPRINT_UD_SCREEN_IN_PX) ?? 0;

private doCloseFolderBackgroundAnimation(): (() => {
    ({
        openFolderLayout: openFolderLayout, : .getGridSwiperLayout().bgHeight = openFolderLayout.getBackgroundLayout().closedHeight,
        openFolderLayout: openFolderLayout, : .getGridSwiperLayout().bgWidth = openFolderLayout.getBackgroundLayout().closedWidth,
        let: let, pos: pos,
        pos: pos,
        let: let, editModeTranslateY: editModeTranslateY,
        if(pos) { }, : .length > 1
    });
    return undefined;
})() {
      let translateXForScreenSplit: number = AppStorage.get<number>('translateXForScreenSplit') ?? 0 as number;
      let screenWidth: number = AppStorage.get<number>('screenWidth') as number;
      let screenHeight: number = AppStorage.get<number>('screenHeight') as number;
      if (screenWidth > screenHeight) {
        log.showInfo('doCloseFolderBackgroundAnimation screenWidth: ' + screenWidth + ', height: ' + screenHeight);
        screenWidth = screenHeight;
      }
      openFolderLayout.getGridSwiperLayout().bgTranslateX = pos[0] - screenWidth / 2 + translateXForScreenSplit;
      openFolderLayout.getGridSwiperLayout().bgTranslateY = pos[1] + editModeTranslateY -
        openFolderLayout.getBackgroundLayout().closedHeight * 0.5 - openFolderLayout.getBackgroundLayout().openedMargin;
    }
}

let f: number = 0.0;
let b5: number = 0;
f = b5; // OK

let e: number = 0.0;
let g1: number = 0;

e += g1; // OK
e -= g1; // OK
e *= g1; // OK
e /= g1; // OK
e <<= g1; // OK
e >>= g1; // OK
e &= g1; // OK
e = e & 3; // OK
e = e | 3; // OK
let arr1: number[] = [1, 2, 3]
e += arr1[0]; // OK

let a: number = 0.0;
a = fun1();
a = fun2()!;

function fun1():number{
  return 1;
}

function fun2():number|undefined{
  return 1;
}

import { ArrayList } from "@kit.ArkTS";

let arr = new ArrayList<number>()
for (let i:number = 0; i < 100; i++) {
  arr.add(i)
}
let cancelIds:ArrayList<number> = arr.subArrayList(6, 86)
let a: Array<number> = Array.from(cancelIds)
let arr1: Array<number> = Array.from(new ArrayList<number>())