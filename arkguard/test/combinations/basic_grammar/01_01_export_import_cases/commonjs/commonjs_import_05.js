/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import assert from 'assert'
require('./commonjs_export_01')
var module1 = require('./commonjs_export_01')
assert(module1.exportApi1 === 'commonjs')
assert(module1.exportApi2(2) === 3)
assert(module1.api() === 'api')
assert(module1.constVal === 2)

const {classExport3Alias, exportObj3} = require('./commonjs_export_01')
assert(exportObj3.obj_prop3 === 3)
let ins3 = new classExport3Alias();
assert(ins3.class3_prop1 === 3);

const default_class = require('./commonjs_export_02')
let ins2 = new default_class();

assert(ins2.class2_prop1 === 2);

const default_obj = require('./commonjs_export_03')
assert(default_obj.obj_prop1 === 1);
assert(default_obj.obj_prop2.inner_prop1 === 2);

const {classExport1, arrowFunc} = require('./commonjs_export_04')
let ins4 = new classExport1();
assert(ins4.class1_prop1 === 1)
assert(arrowFunc(2) === 12)