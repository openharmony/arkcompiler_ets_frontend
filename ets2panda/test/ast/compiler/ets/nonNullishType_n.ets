/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

class Test{}

class A<T> {
  foo(a: T):Test!{
    let b : Object! = new Object();
    let c : (int)! = 0;
    return a!;
  }
}

/* @@? 19:13 Error TypeError: Only type parameters can be used as a nonnullish type  */
/* @@? 20:13 Error TypeError: Only type parameters can be used as a nonnullish type  */
/* @@? 21:13 Error TypeError: Only type parameters can be used as a nonnullish type  */
/* @@? 22:12 Error TypeError: Type 'NonNullable<T>' is not compatible with the enclosing method's return type 'Test'  */
/* @@? 22:12 Error TypeError: Type 'NonNullable<T>' is not compatible with the enclosing method's return type 'Test'  */
