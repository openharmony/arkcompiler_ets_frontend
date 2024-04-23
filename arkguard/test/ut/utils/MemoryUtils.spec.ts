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

import {assert} from 'chai';
import {MemoryUtils} from '../../../src/utils/MemoryUtils';

describe('test for MemoryUtils', function () {
  const disableGC = false;
  const allowGC = true;
  const iniBaseMemory = undefined;
  const lowBaseLine = 0;
  const highBaseLine = 1000 * 1024 * 1024; // 1000MB
  const highBase = 1000 * 1024 * 1024; // 1000MB

  describe('test for method tryGC', function () {
    it('test for allowGC === true', function () {
      MemoryUtils.setGC(allowGC);
      MemoryUtils.setBaseMemorySize(iniBaseMemory);
      assert.strictEqual(MemoryUtils.getBaseMemorySize(), undefined);

      // Initialize base
      MemoryUtils.tryGC();
      assert.notEqual(MemoryUtils.getBaseMemorySize(), undefined);

      // Trigger GC
      MemoryUtils.setBaseLine(lowBaseLine);
      const memoryBeforeGC = process.memoryUsage().heapUsed;
      MemoryUtils.tryGC();
      assert.isAbove(MemoryUtils.getBaseMemorySize(), 0);
      assert.isBelow(MemoryUtils.getBaseMemorySize(), memoryBeforeGC);

      // Lower base
      MemoryUtils.setBaseLine(highBaseLine);
      MemoryUtils.setBaseMemorySize(highBase);
      MemoryUtils.tryGC();
      assert.isBelow(MemoryUtils.getBaseMemorySize(), highBase);
    });

    it('test for allowGC === false', function () {
        MemoryUtils.setGC(disableGC);
        MemoryUtils.setBaseMemorySize(iniBaseMemory);
        assert.strictEqual(MemoryUtils.getBaseMemorySize(), undefined);
        MemoryUtils.tryGC();
        assert.strictEqual(MemoryUtils.getBaseMemorySize(), undefined);
    });
  });
});