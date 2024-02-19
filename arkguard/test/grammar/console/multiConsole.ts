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

function foo() {
  console.error('This is an error message.');
  console.warn('This is a warning message.');
  console.info('This is an informational message.');
  console.debug('This is a debug message.');
  console.assert(1 === 2, 'This assertion failed.');
  const obj = { name: 'John', age: 30 };
  console.dir(obj);
  const data = [{ id: 1, name: 'John' }, { id: 2, name: 'Jane' }];
  console.table(data);
  console.time('timer');
  console.timeEnd('timer');
}