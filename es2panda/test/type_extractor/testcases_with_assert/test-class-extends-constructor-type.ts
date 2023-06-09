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


declare function AssertType(value: any, type: string): void;

type Constructor<T> = new (...args: any[]) => T;

interface IEventified {
  emit(str: string): void;
}

function Eventify<TBase> (base: Constructor<TBase>): Constructor<TBase & IEventified> {
  AssertType(base, "any");
  class Eventified extends (base as unknown as any) {};
  return Eventified as unknown as Constructor<TBase & IEventified>;
}
AssertType(Eventify, "(any) => any");

class Base {
  say() {
    print('Hello');
  }
};

class MyClass extends Eventify(Base) {
  emit(str: string): void {
    print(str);
  }
};

function test(o: MyClass): string {
  AssertType(o, "MyClass");
  o.say();
  o.emit('World');
  return "OK";
}
AssertType(test, "(MyClass) => string");

let myclass = new MyClass();
AssertType(myclass, "MyClass");
AssertType(myclass.emit, "(string) => void");

let ret = test(myclass);
AssertType(ret, "string");