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

type Ctor<T> = new () => T;

function classConstructorTypeTest(ctor: Ctor<MyClass>)
{
  const obj = new ctor();
  AssertType(ctor, "any");
  AssertType(obj, "any");
  return obj;
}

function typeOfClassTest(ctor: typeof MyClass)
{
  const obj = new ctor;
  AssertType(ctor, "any");
  AssertType(obj, "any");
  return obj;
}

class MyClass {
  public id: number = 1;
  constructor() {};
}

let obj1 = new MyClass();

const myctor = MyClass;
let obj2 = classConstructorTypeTest(myctor);
let obj3 = typeOfClassTest(myctor);

AssertType(obj1, "MyClass");
AssertType(obj2, "any");
AssertType(obj3, "any");