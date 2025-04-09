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

'use static'
import {Foo, Foo1} from "./instantiated_js_obj_js"
class A {
    num: number = 1;
    constructor() {
    }
}
new Foo(123)
new Foo('hello')
new Foo(new A())
let a: A = new A();
new Foo(a.num)
new Foo(a)
function test(): number {
  return 1;
}
new Foo(test())
new Foo1(123, 'hello')