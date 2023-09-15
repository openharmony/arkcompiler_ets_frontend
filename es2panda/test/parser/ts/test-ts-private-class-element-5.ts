/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


class C {
  #value: number = 0;
  #add() {
    this.#value += 1;
  }
  publicAdd() {
    this.#add();
  }
  publicPrint() {
    print(this.#value);
  }

  static #message: string = "hello";
  static #say() {
    return this.#message;
  }
  static publicSay() {
    print(this.#say());
  }

  get #data() {
    return this.#value;
  }
  set #data(num: number) {
    this.#value = num;
  }
  get publicData() {
    return this.#data;
  }
  set publicData(num: number) {
    this.#data = num;
  }

  static get #msg() {
    return this.#message;
  }

  static set #msg(msg: string) {
    this.#message = msg;
  }

  static set publicMsg(msg: string) {
    this.#msg = msg;
  }
  static get publicMsg() {
    return this.#msg;
  }
}

let c: C = new C();
c.publicAdd();
c.publicPrint();
C.publicSay();
c.publicData = 20;
print(c.publicData)
C.publicMsg = 'hi';
print(C.publicMsg);

