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

import fs from 'fs';
import path from 'path';
import assert from 'assert';

const filePath = path.join(__filename, '../stringLiteral_demo_02_use.ts');
const actual = fs.readFileSync(filePath, 'utf-8');

const expectation = `interface Interface11 {
    "interfaceP12": number;
    ["interfaceP13"]: number;
}
const Object11 = {
    "objectP12": 11,
    ['objectP13']: 12,
};
class class11 {
    'classP12' = 3;
    ['classP13'] = 2;
}
enum enum11 {
    'enumP12',
    ['enumP13']
}
Object11['paramerter01'];`

assert.strictEqual(actual.trim(), expectation.trim());