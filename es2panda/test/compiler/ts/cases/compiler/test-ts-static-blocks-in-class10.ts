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


// In static blocks in classes if "this" refer to the class itself, it should be transformed to the class itself
class C {
  static s1: number = 1;
  static {
    print(this.s1);
    print(C.s1);
    print(this.s2);
    print(C.s2);
  }
  static s2: number = 2;
  static s3: number = this.s1;
}
print(C.s2);
print(C.s3);