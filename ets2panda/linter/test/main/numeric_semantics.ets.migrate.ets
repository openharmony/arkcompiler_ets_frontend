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

import {
  Entry,
  Component,
  State,
  RelativeContainer,
  Text,
  AppStorage,
} from '@kit.ArkUI';

let a: number = 1.0;

a = 1.0; // OK
a = 1.5; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'

a += 1.0; // OK
a += 1.5; // ArkTS: Result is integer value

console.log(a + 1.0); // OK
console.log(a - 0.5); // OK
console.log(a / 2.0); // ArkTS: integer division is used, result is integer value
console.log(a / 2.5); // OK
console.log(2.0 / a); // ArkTS: integer division is used, result is integer value
console.log(2.5 / a); // OK

let b: number = 1.0;
a = b; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'
a += b; // ArkTS: Result is integer value
console.log(a + b); // OK
console.log(a / b); // OK

let c: number = 1.5;
a = c; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'
a += c; // ArkTS: Result is integer value
console.log(a + c); // OK
console.log(a / c); // OK

let d: number = 2.0;
a = d; // OK
a += d; // OK
console.log(a + d); // OK
console.log(a / d); // ArkTS: integer division is used, result is integer value

let n: number = 2.0;

let f: number = 1.0

let g: number[] = [1.0, 2.0, 3.0]

let x!: number

let t8: number = Infinity

let t9: number = -Infinity;

let t10: number = NaN;

let t11: number = Number.MAX_VALUE;

let t12: number = Number.MIN_VALUE;

let o:number = 123.0;

const oo:number = 123.0;

let o2: number = o; 

let o3: number = oo; 

class A{
   a: number = 1.0;
   constructor() {
  }
}

let t2: number = +123.0;

let t3: number = -234.0;

let num: number = Math.floor(4.8); // num 可能是 int

let value: number = parseInt("42"); // value 可能是 int


function multiply(x: number = 2.0, y: number = 3.0): number { 
 return x * y;
}

function divide(x: number, y: number): number {
  return x / y;
}

function identity<T>(value: T): T {
  return value;
}
identity(42.0);

let an_array: number[] = [1.0,2.0,3.0]

let g2: number = an_array[]

const a2: number = 1.0

enum Test {
  A = 1,  // 显式赋值为 1
  B = 2   // 显式赋值为 2
}
const test: number = Test.A;

@Entry
@Component
struct Index2 {
  @State message: string = 'Hello World';
  readonly c1: number = 1.0; // int
  readonly c4: number = 1.7; // float
  readonly c5: number = 0x123; // 16进制
  readonly c6: number = 0o123; //8进制
  readonly c7: number = 0b101; //2进制
  readonly c8: number[] = [1.0,2.0,3.0]

build() {
    RelativeContainer() {
      Text(this.message)
        .onClick(() => {
        })
    }
  }
}

const c1: number = 1.0;

export class G{
  readonly a5: number = 4.0;
}

const fingerprintPositionY: number = AppStorage.get<number>(FingerprintConstants.COORDINATE_Y_OF_FINGERPRINT_UD_SCREEN_IN_PX) ?? 0.0;

class Layout {
  private doCloseFolderBackgroundAnimation(): void {
    openFolderLayout.getGridSwiperLayout().bgHeight = openFolderLayout.getBackgroundLayout().closedHeight;
    openFolderLayout.getGridSwiperLayout().bgWidth = openFolderLayout.getBackgroundLayout().closedWidth;

    let pos: number[] = [-1.0, -1.0];
    pos = folderLayoutUtil.getFolderComponentCenterPosition(FolderData.getInstance().getOpenedFolder());
    let editModeTranslateY = this.getEditModeTranslateY(pos);
    if (pos.length > 1.0) {
      let translateXForScreenSplit: number = AppStorage.get<number>('translateXForScreenSplit') ?? 0.0 as number;
      let screenWidth: number = AppStorage.get<number>('screenWidth') as number;
      let screenHeight: number = AppStorage.get<number>('screenHeight') as number;
      if (screenWidth > screenHeight) {
        log.showInfo('doCloseFolderBackgroundAnimation screenWidth: ' + screenWidth + ', height: ' + screenHeight);
        screenWidth = screenHeight;
      }
      openFolderLayout.getGridSwiperLayout().bgTranslateX = pos[0] - screenWidth / 2.0 + translateXForScreenSplit;
      openFolderLayout.getGridSwiperLayout().bgTranslateY = pos[1] + editModeTranslateY -
        openFolderLayout.getBackgroundLayout().closedHeight * 0.5 - openFolderLayout.getBackgroundLayout().openedMargin;
    }
  }
}

let f2: number = 0.0;
let b5: number = 0.0;
f = b5; // OK

let e: number = 0.0;
let g1: number = 0.0;

e += g1; // OK
e -= g1; // OK
e *= g1; // OK
e /= g1; // OK
e <<= g1; // OK
e >>= g1; // OK
e &= g1; // OK
e = e & 3.0; // OK
e = e | 3.0; // OK
let arr1: number[] = [1.0,2.0,3.0]
e += arr1[0]; // OK

let a3: number = 0.0;
a3 = fun1();
a3 = fun2()!;

function fun1():number{
  return 1.0;
}

function fun2():number|undefined{
  return 1.0;
}

import { ArrayList } from "@kit.ArkTS";

let arr2 = new ArrayList<number>()
for (let i:number = 0.0; i < 100.0; i++) {
  arr2.add(i)
}
let cancelIds:ArrayList<number> = arr2.subArrayList(6.0, 86.0)
let arr3: Array<number> = Array.from(cancelIds)
let arr4: Array<number> = Array.from(new ArrayList<number>())

let a4: number = 0.000;

const b4: number = 0.000;

export enum WalletStageValue {
  DEFAULT = 0,
  SWIPE_INIT = -1,
  SELECT_CARD = 1,
  SWIPE_DOING = 2,
  SWIPE_SUCCEED = 3,
  SWIPE_FAILED = 4,
  SWIPE_FINISHED = 5,
}

export enum AnimationStage {
  INIT = 0,
  ENTER = 1,
  ROTATING = 2,
  EXIT_START = 3,
  EXIT_END = 4,
}

class C {
  public static readonly SIX_MONTH: number = 180.0 * 24.0 * 60.0 * 60.0 * 1000.0
}

function testIndentation(): void {
  let a: number = (() => {
    console.log('hello');
    return 0.0;
  })();
}


export function add(a: number, b: number): number {
  console.log("SharedModule: Hap call ShareFile add");
  return a + b;
} 