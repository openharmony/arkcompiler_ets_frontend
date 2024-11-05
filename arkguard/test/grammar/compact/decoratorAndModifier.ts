/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

function logClassName(constructor: Function) {
  console.log(`Class name: ${constructor.name}`);
}

function logProperty1(target: any, key: string) {
  console.log(`Property name: ${key}`);
}
function logProperty2(target: any, key: string) {
  console.log(`Property name: ${key}`);
}

@logClassName
class ExampleClass {
  @logProperty1 @logProperty2
  private someProperty: string; // commentssssss
  @logProperty2
  @logProperty1
  public secondProperty: number;

  @logProperty1
  async foo(): Promise<any> { }
}
function foo() {
  let a1 = 1
  let a2 = 2;
  let a3 = 3
  let a4 = 4
  let a5 = 5
}