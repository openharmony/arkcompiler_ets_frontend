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

let a = {
  0b1: 1,
  0o2: 2,
  0x3: 3,
  1e2: 100,
}
print(a[0b1])
print(a[0o2])
print(a[0x3])
print(a[1e2])
print(a[1])
print(a[2])
print(a[3])
print(a[100])

let b = {
  1: 1,
  2: 2,
  3: 3,
  100: 100,
}
print(b[1])
print(b[2])
print(b[3])
print(b[100])
print(b[0b1])
print(b[0o2])
print(b[0x3])
print(b[1e2])