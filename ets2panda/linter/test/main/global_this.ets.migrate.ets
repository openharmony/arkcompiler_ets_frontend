/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

const pi: number = 3.1416;

function circleArea(r: number): number {
  foo(globalThis);

  return specialAutofixLib.globalThis.get("pi") * r * r;
}

function foo(x: any): void {
  console.log(x.pi);
}

specialAutofixLib.globalThis.set("abc", 200);

const value = specialAutofixLib.globalThis.get("obj").prop;

delete specialAutofixLib.globalThis.get("property");

globalThisprop = 100;

specialAutofixLib.globalThis.get("pi");

specialAutofixLib.globalThis.set("pi",3.1416);

specialAutofixLib.globalThis;

