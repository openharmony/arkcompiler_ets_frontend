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

function foo(left: number = 0, right: number): number {
  return left + right
}

function foo3(a: number, b: number = 5, c: number): number {
  return a + b + c;
}

function foo4(a: number = 1, b: number = 2, c: number): number {
  return a + b + c;
}

function foo5(a: number = 1, b: number = 2, c: number = 3): number { //legal
  return a + b + c;
}

const bar = (x: boolean = true, y: boolean) => {
  return x && y;
};

class MyClass {
  myMethod(x: number = 0, y: number) {
    return x + y;
  }
}

function fooLegal(a: number, b: number = 0): number { //legal
  return a + b;
}

function greetLegal(name: string, message: string = "Hi"): string { //legal
  return message + ", " + name;
}

const barLegal = (x: boolean, y: boolean = false) => { //legal
  return x && y;
};

function log(level: string = 'info', some: string, message?: string): void {
  console.log(`${some} [${level.toUpperCase()}] ${message ?? 'No message'}`);
}

function config(debug: boolean = true, verbose?: boolean): string { //legal
  return `Debug: ${debug ?? false}, Verbose: ${verbose ?? false}`;
}

export class DefaultArgsA {
  readonly left: number;
  readonly right: number;
  constructor(left: number = 0.0, right: number) { // 漏扫
    this.left = left;
    this.right = right;
  }

  defaultArgsFoo1(left: number = 0.0, right: number): number {
    return left + right;
  }
}