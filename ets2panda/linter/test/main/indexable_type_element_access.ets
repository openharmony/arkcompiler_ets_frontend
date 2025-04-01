/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

class ClassWithGet {
  $_get(index: number): ClassWithGet {
    return this;
  }
}
let getClass = new ClassWithGet();
getClass = getClass[0];
getClass[0] = getClass; // Error - no $_set function available

class ClassWithSet {
  $_set(index: number, value: ClassWithSet) {}
}
let setClass = new ClassWithSet();
setClass = setClass[0]; // Error - no $_get function available
setClass[0] = setClass;

class ClassWithGetAndSet {
  $_get(index: number): ClassWithGetAndSet {
    return this;
  }

  $_set(index: number, value: ClassWithGetAndSet) {}
}
let getSetClass = new ClassWithGetAndSet();
getSetClass = getSetClass[0]; 
getSetClass[0] = getSetClass;
