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

function f(a: PropertyDescriptor) {
 a.configurable;
 a.enumerable;
 a.value;
 a.writable;
 a.get;
 a.set;
}

let desc: TypedPropertyDescriptor<number> = {
  value:1,
  get():number {return this.value},
  set(v): void {this.value = v},
  enumerable: false,
  configurable: false,
  writable: true
}

type MyPropertyDescriptor = PropertyDescriptor;
type MyTypedPropertyDescriptor<T> = TypedPropertyDescriptor<T>;

function f(a: MyPropertyDescriptor) {
    a.configurable;
    a.enumerable;
    a.value;
    a.writable;
    a.get;
    a.set;
}

let desc: MyTypedPropertyDescriptor<number> = {
    value: 1,
    get(): number { return this.value; },
    set(v): void {this.value = v},
    enumerable: false,
    configurable: false,
    writable: true
};

interface APropertyDescriptor {}
interface PropertyDescriptorA {}
interface PropertyDescriptor {}

let a1: APropertyDescriptor = {}
let a2: PropertyDescriptorA = {}
let a3: PropertyDescriptor = {}