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

try {
  "use strict";
  var iterable = {};

  iterable[Symbol.iterator] = function() {
    return {
      next: function() {
        return { done: false, value: 1 };
      },
      return: 1
    };
  };

  for (let i of iterable) {
    print(i);
    throw "123";
  }
} catch (e) {
  print(e);
}
