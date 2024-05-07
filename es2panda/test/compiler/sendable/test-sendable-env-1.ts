/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

class A{
  static a: number = 2;
  constructor() {
    'use sendable'
    A.a =1;
  }

  test() {
    class B{
      constructor(){
        'use sendable'
        A.a =3;
      }
    }
    
    let b = new B();
  }
}

print(A.a);
let a = new A();
print(A.a);
a.test();
print(A.a);
  