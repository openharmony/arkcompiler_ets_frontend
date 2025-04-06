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

const isTrue = true;
switch (isTrue) {
  case true:
    console.log('It\'s true');
    break;
  case false:
    console.log('It\'s false')
    break;
}

let objValue = { key: "value" };

switch (objValue) {
  case { key: "value" }:
    console.log("Matching object!");
    break;
  default:
    console.log("Non-matching object");


let arrayValue = [1, 2, 3];

switch (arrayValue) {
  case [1, 2, 3]:
    console.log("Matching array!");
    break;
  default:
    console.log("Non-matching array");
}

const isT = 'true';
switch (isT) {
  case 'true':
    console.log('It\'s true');
    break;
  case 'false':
    console.log('It\'s false')
    break;
}

const number1 = 1;
switch (number1) {
  case 1:
    console.log('It\'s 1');
    break;
  case 2:
    console.log('It\'s 2')
    break;
}

enum Test {
  A = 1,
  B = 2
}
const test = Test.A
switch (test) {
  case Test.A:
    console.log('It\'s A');
    break;
  case Test.B:
    console.log('It\'s B')
    break;
}

const number2 = -1.1;
switch (number2) {
  case -1.1:
    console.log('It\'s 1');
    break;
  case 2:
    console.log('It\'s 2')
    break;
}

const number3 = Number.NaN;
switch (number3) {
  case -1.1:
    console.log('It\'s 1');
    break;
  case 2:
    console.log('It\'s 2');
    break;
}

const number4 = Number.MAX_VALUE;
switch (number4) {
  case -1.1:
    console.log('It\'s 1');
    break;
  case 2:
    console.log('It\'s 2');
    break;
}

let day:int = 2;
let dayName = "empty";
switch (day) {
    case 0:
        dayName = "Sunday";
        break;
    case 1:
        dayName = "Monday";
        break;
    case 2:
        dayName = "Tuesday";
        break;
    case 3:
        dayName = "Wednesday";
        break;
    case 4:
        dayName = "Thursday";
        break;
    case 5:
        dayName = "Friday";
        break;
    case 6:
        dayName = "Saturday";
        break;
    default:
        dayName = "Unknown";
}