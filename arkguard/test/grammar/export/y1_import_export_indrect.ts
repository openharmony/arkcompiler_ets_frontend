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

import assert from 'assert';

import { default as varAlis2 } from './y1_export_default_value';
import defaultExport2, { CDE11 } from './y1_import_alias';

let ins = new CDE11.ClassAlis;
assert(ins.classProp1 === 2, 'success');
type typeAlis = CDE11.InterOriginal2;
assert(CDE11.fooOriginal2() === '11', 'success');
assert(defaultExport2() === 22, 'success');
assert(varAlis2 === 15, 'success');