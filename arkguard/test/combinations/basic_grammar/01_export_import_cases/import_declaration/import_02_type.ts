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
import typeAlias4, {typeAlias1, type typeAlias2} from './export_type_03'
import type { typeAlias3} from './export_type_03'
import type {default as typeAlias_new4 } from './export_type_03'
import type { as } from './export_type_03'
import * as module2 from './export_type_03'
import * as type from './export_type_03'

let num1: typeAlias1 = 1;
let num2: typeAlias2 = 'blank';
let num3: typeAlias3 = false;
let num4: typeAlias_new4 = 4;
let num5: as;
let num6: module2.typeAlias1 = 6;
let num7: type.typeAlias1 = 7;

import { moduleAlias } from './import_01_from'
assert(moduleAlias.addFunc(3, 4) === 7);