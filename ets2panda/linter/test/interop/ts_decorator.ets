'use static'
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

import { decorator1, decorator2, readonly1 } from "./oh_modules/ts_decorator"
import { MyNs } from "./oh_modules/ts_decorator"
import { Lib } from "./oh_modules/ts_decorator"
import { MyDecorator } from "./oh_modules/ets_decorator";

@decorator1
class K { }

@Entry // legal
class X { }

@MyDecorator //legal
class Y { }

class Example {
  @decorator2
  doSomething() { return "hello" }
}

class Person {
  private _age: string;
  @readonly1(true)
  get age(): string {
    return this._age;
  }
}

@MyNs.myDecorator()
class C { }

@decorator1
@MyNs.myDecorator()
class MyClass {
  @decorator2
  @readonly1(true)
  myMethod() { }

  @Lib.Utils.decorator()
  myProperty = 'value';
}
