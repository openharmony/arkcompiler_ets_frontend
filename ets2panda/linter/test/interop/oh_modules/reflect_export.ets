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

export function foo(prx: Object) {
 Reflect.get(prx, 'a')  // 'hello'
 Reflect.set(prx, 'a', 'world')  // true
 Reflect.ownKeys(prx)  // ['a']
}

export function bar(obj: Object) {
    return Reflect.has(obj, 'prop');
}

export class X {
    a: string = 'hello'
    getName() { return this.a }
}

export class Reflect1 {
  a: string = 'hello'
  getName() { return this.a }
}
export let obj_Reflect1 = new Reflect1();

interface Iface {
  a:number
}
export let objInter:Iface = {a:1}

export function reflect_method1(prx: ESObject) {
  Reflect.ownKeys(prx)  // ['a']
  Reflect.set(prx, 'a', 7)  // true
  Reflect.get(prx, 'a')  // true
  Reflect.has(prx, 'a')  // true
}

export function reflect_method1_set(prx: ESObject) {
  Reflect.set(prx, 'a', 7)  // true
}

export function reflect_method1_get(prx: ESObject) {
  Reflect.get(prx, 'a')  // true
}

export function reflect_method1_ownKeys(prx: ESObject) {
  Reflect.ownKeys(prx)  // ['a']
}

export function reflect_method1_has(prx: ESObject) {
  Reflect.has(prx, 'a')  // true
}
