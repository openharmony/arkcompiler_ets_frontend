/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

// #14071
class A {
  v: string = '';
}
function SetProperty<T extends Object>(oldObj: T, str: string, obj: Object): void {
  oldObj[str] = obj; // Should report error
}
function GetProperty<T extends Object, U>(oldObj: T, str: string): U {
  return oldObj[str]; // Should report error
}
function test() {
  let a: A = { v: 'abc' };
  SetProperty(a, 'u', 'def');
  return GetProperty<A, string>(a, 'v') + GetProperty<A, string>(a, 'u');
}
