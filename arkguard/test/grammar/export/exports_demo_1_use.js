/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

const assert = require('assert');

const myModule = require('./exports_demo_1');

assert.strictEqual(myModule.myExportVar, 0);

assert.strictEqual(myModule.myVariable, 1);
assert.strictEqual(myModule.myFunction(), 'Hello, world!');

let myclass3 = new myModule.MyClass3()
assert.strictEqual(myclass3.id3, '00001');
assert.strictEqual(myclass3.info3.name3, 'jack3');
assert.strictEqual(myclass3.info3.age3, 12);

let myclass4 = new myModule.noNameClass();
myclass4.stuAge = 16;
assert.strictEqual(myclass4.stuID, 11);
assert.strictEqual(myclass4.getAge(), 16);