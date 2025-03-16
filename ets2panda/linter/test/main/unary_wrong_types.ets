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

function gets(): string {
  return 'ss';
}

function getTen(): string {
  return '-10';
}

const a1 = +'3';
const a2 = -'3';
const a3 = ~'3';
const a4 = +gets();
const a5 = ~3.14; // non-integer literal
const a6 = +getTen();

const b1 = !'b';
const b2 = !'';

console.log(a1);
console.log(a2);
console.log(a3);
console.log(a4);
console.log(a5);
console.log(b1);
console.log(b2);
