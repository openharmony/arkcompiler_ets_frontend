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

import {describe, it} from 'mocha';
import {assert} from 'chai';

describe('opaque predicate test', function () {
  const maxValueFirst = 125;
  it('test y < 10 || x * (x + 1) % 2 == 0;', function () {
    for (let i = 0; i <= maxValueFirst; i++) {
      for (let j = 0; j <= maxValueFirst; j++) {
        assert.isTrue(j < 10 || i * (i + 1) % 2 === 0);
      }
    }
  });

  it('test 7* x* x − y* y != 1 || y < n;', function () {
    for (let i = 0; i <= maxValueFirst; i++) {
      for (let j = 0; j <= maxValueFirst; j++) {
        assert.isTrue(7 * i * i - j * j !== 1);
      }
    }
  });

  const maxValueSecond = 10000;
  it('test (4*x*x + 4) mod 19 != 0;', function () {
    for (let i = 0; i <= maxValueSecond; i++) {
      assert.isTrue((4 * i * i + 4) % 19 !== 0);
    }
  });

  it('test (x*x + x +7) % 81 != 0;', function () {
    for (let i = 0; i <= maxValueSecond; i++) {
      assert.isTrue((i * i + i + 7) % 81 !== 0);
    }
  });

  it('test (x*x*x - x) % 3 == 0;', function () {
    for (let i = 0; i <= maxValueSecond; i++) {
      assert.isTrue((i * i * i - i) % 3 === 0);
    }
  });
});
