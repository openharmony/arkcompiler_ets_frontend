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


// 4. static accessors can be named with a private identifier

let CC4 = class C4 {
  static #message: string = "";
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

CC4.publicMsg = 'hi';
print(CC4.publicMsg);
