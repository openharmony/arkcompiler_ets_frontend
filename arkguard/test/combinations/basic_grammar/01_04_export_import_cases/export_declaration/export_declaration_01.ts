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

export function foo1() { return 1 }
export function* foo2() {
  yield 1;
  return 2;
}
export async function foo3() { return 3 }
export async function* foo4() { return 4 }

export class className1 {
  prop: string = "hello";
}

export let var1 = 1;
export let var2 = 2, var3 = 3;

export const var4 = 4;
export const var5 = 5, var6 = 6;