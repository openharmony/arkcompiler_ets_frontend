/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import {
  clearUnobfuscationNamesObj,
  unobfuscationNamesObj
} from '../../../src/initialization/CommonObject';
import { expect } from 'chai';

describe('Tester Cases for <CommonObject.ts>.', function () {
  it('Tester Cases for <clearUnobfuscationNamesObj>.', function () {
    unobfuscationNamesObj['prop1'] = 1;
    unobfuscationNamesObj['prop2'] = 2;
    expect(Object.keys(unobfuscationNamesObj).length).to.equal(2);
    clearUnobfuscationNamesObj();
    expect(Object.keys(unobfuscationNamesObj).length).to.equal(0);
  });
});
