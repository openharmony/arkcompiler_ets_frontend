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
let GeneratedImportVar_1 = ESObject.load('./instantiated_js_obj_js');
let Foo = GeneratedImportVar_1.getPropertyByName('Foo');
let Foo1 = GeneratedImportVar_1.getPropertyByName('Foo1');

class A {
    num: number = 1;
    constructor() {
    }
}
Foo.instantiate(ESObject.wrap(123))
Foo.instantiate(ESObject.wrap('hello'))
Foo.instantiate(ESObject.wrap(new A()))
let a: A = new A();
Foo.instantiate(ESObject.wrap(a.num))
Foo.instantiate(ESObject.wrap(a))
function test(): number {
  return 1;
}
Foo.instantiate(ESObject.wrap(test()))
Foo1.instantiate(ESObject.wrap(123), ESObject.wrap('hello'))