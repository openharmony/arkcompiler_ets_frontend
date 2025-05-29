/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export class User {
  id: number;
  constructor(arg: number) {
    this.id = arg
  }
}
export class Person {
  name: string;
  age: number;
  constructor(arg1: string, arg2: number) {
    this.name = arg1;
    this.age = arg2;
  }
}
export class Fruit {
  name: string;
  constructor(arg: string) {
    this.name = arg;
  }
}
export class Apple extends Fruit {
  color: string;
  constructor(string: string, arg2: string) {
    super(string)
    this.color = arg2;
  }
}

export class X {
    name: string = "";
    constructor(arg: string) {
      this.name = arg;
    }
}

export interface Y {data: number} 
export function foo(arg: X){}
export function bar(arg: Y){}
