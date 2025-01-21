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
    clearHistoryUnobfuscatedMap,
    historyAllUnobfuscatedNamesMap,
    historyUnobfuscatedPropMap
} from '../../../src/initialization/Initializer';
import { expect } from 'chai';

describe('Tester Cases for <Initializer.ts>.', function () {
  it('Tester Cases for <clearHistoryUnobfuscatedMap>.', function () {
    historyAllUnobfuscatedNamesMap.set('key', {'prop1': 'aaa'});
    historyUnobfuscatedPropMap.set('key', ['value']);
    expect(historyAllUnobfuscatedNamesMap.size).to.equal(1);
    expect(historyUnobfuscatedPropMap.size).to.equal(1);
    clearHistoryUnobfuscatedMap();
    expect(historyAllUnobfuscatedNamesMap.size).to.equal(0);
    expect(historyUnobfuscatedPropMap.size).to.equal(0);
  });
});
