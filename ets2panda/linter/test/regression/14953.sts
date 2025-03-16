/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

const str1 = 'a';

enum T {
  A = 'aaa',
  B = 'bbb'
}

let obj: Record<string, number> = {
  ['b']: 123,
  [T.A]: 234,
  [T.B]: 345
};

let obj2: Record<string, number> = {
  [str1]: 111, // error
};

class A {
  ['b']: 123;
  [T.A]: 345;
  [T.B]: 456;
  [str1]: 234; // error
};
