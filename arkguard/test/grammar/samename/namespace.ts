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

let config = "123";
const obj = {config: config};

let xFnexp = 1, fnexp = 2;
async function fn() {
  for await ({ xFnexp = xFnexp, fnexp = xFnexp } of [{ xFnexp, fnexp }]) {
    assert.strictEqual(xFnexp, 1);
    assert.strictEqual(fnexp, 2);
  }
}
