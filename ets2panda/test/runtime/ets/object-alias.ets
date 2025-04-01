/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

function main(): void {
  let a: object = new object();
  let b: object = new Object();
  let c: Object = new object();
  let d: Object = new Object();

  assertTrue(a instanceof Object)
  assertTrue(a instanceof object)
  assertTrue(b instanceof Object)
  assertTrue(b instanceof object)
  assertTrue(c instanceof Object)
  assertTrue(c instanceof object)
  assertTrue(d instanceof Object)
  assertTrue(d instanceof object)
}
