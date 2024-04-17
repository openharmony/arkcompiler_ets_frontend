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

const filePath = path.join(__filename, '../stringLiteral_demo_01_use.ts');
const actual = fs.readFileSync(filePath, 'utf-8').toString();

const expectation = `const stringLiteralObj02 = {
    "'": 11,
    '"': 22,
    '\\\\': 33,
    '\\b': 44,
    '\\f': 55,
    '\\n': 66,
    '\\r': 77,
    '\\t': 88,
    '\\v': 99,
    '\\0': 100,
    '\\u2028': 111,
    '\\u2029': 122,
};`

assert.strictEqual(actual.trim(), expectation.trim());
