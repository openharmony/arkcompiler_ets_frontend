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


import { libPi, libString, libFoo, LibClass, libClassVar, LibRGB } from './sendable_captured_variables_lib'

import libVar from './sendable_captured_variables_lib' 

let localVar = 'local';

function localFun(): string {
  return "local foo";
}

class LocalClass {
  a: number = 1;
  static b: string = '2';
  foo(): void {}
  static bar(): void {}
}

let localObj: LocalClass = new LocalClass();

enum LocalRGB {
  RED,
  GREEN,
  BLUE
}

@Sendable
class SendableClass {
  static pi: number = libPi;
  static hdr: string = libString;
  public p = localVar; // ERROR
  static ps = localVar; // ERROR
  sc: SendableClass2 = new SendableClass2(); // ERROR

  public foo(x: string): string {
    let s = localVar; // ERROR
    let ss = this.p + SendableClass.ps + x;
    s = localFun(); // ERROR
    s = libFoo();
    return s + ss;
  }

  bar(a: SendableClass2) { // ERROR
    let b = a;
    a.a = 2;
  }

  baz(): SendableClass2 { // ERROR
    return new SendableClass2(); // ERROR
  }
  
  bazz(): void {
    let a: LibRGB = LibRGB.GREEN;
    console.log(LibRGB.RED);
    
    let b: LocalRGB; // ERROR
    b = LocalRGB.RED; // ERROR
    console.log(LocalRGB.BLUE); // ERROR
  }

  static {
    SendableClass.ps = localVar; // ERROR
    let lc: LocalClass; // ERROR
    lc = new LocalClass(); // ERROR
    console.log(lc.a);
    console.log(LocalClass.b); // ERROR
    lc.foo();
    LocalClass.bar(); // ERROR
    lc = localObj; // ERROR
    console.log(localObj.a); // ERROR
    localObj.foo(); // ERROR

    let pps: string = libString;
    let libv: number = libVar;
    let libc: LibClass;
    libc = libClassVar;

    console.log(libc.a);
    console.log(LibClass.b);
    libc.foo();
    LibClass.bar();
  }
}

@Sendable
class SendableClass2 {
    a: number = 1;
}

@Sendable
class C {
  static a: number = 1;
  f() {
    @Sendable
    class D {
      b: number = C.a; // ERROR
    }
  }
}