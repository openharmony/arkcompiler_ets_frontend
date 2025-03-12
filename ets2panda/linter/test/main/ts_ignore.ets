/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

// @ts-ignore
let x: number = null; // No error, type checking is suppressed
let y: number = null; // Compile-time error

if (false) {
  /* @ts-ignore: Unreachable code error */
  console.log("hello");
}

let a: number = 0 // @ts-ignore: suppresses CTE for the next line
let b: number = null;



        // @ts-expect-error
console.log("Hello" * 42);

 /*
 @ts-expect-error (shouldn't be reported)
*/
console.log("Hello" * 42);

// no @ts-expect-error (shouldn't be reported)
console.log("Hello" * 42);

const l1 = (): void => {
    let l2 = () => {
        // @ts-expect-error
        console.log("Hello" * 42);
    }
    l2();
}

l1();

class SomeClass {
  // @ts-ignore
  static readonly m1;

  methodError(param: any) {
        // @ts-expect-error
        console.log("Hello" * param);
        // @ts-ignore
        let nns: String = null;
  }
}

class ChainedCallsClass {
    methodOne(): ChainedCallsClass {
        return this;
    }

    methodTwo(): ChainedCallsClass {
        return this;
    }
}

// Issue 13972
let cc = new ChainedCallsClass()
// @ts-ignore
.methodOne().methodTwo();

// #14305
/*
@ts-ignore (shouldn't be reported)
 */
let c: number = '1';

/*
 @ts-ignore (shouldn't be reported)
 */
let d: number = '1';