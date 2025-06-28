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


let numStr = `{
    "numberval1": 1.79e+308,
    "numberval2": 1.7976931348623158e+309,
    "numberval3": 5e+320,
    "numberval4": 2.225e-308,
	"numberval5": 2.225e-309,
	"numberval6": 3e-320,
	"numberval7": 5e-324,
	"numberval8": 5e-325,
	"numberval9": 7e-350,
	"numberval10": -1.79e+308,
    "numberval11": -1.7976931348623158e+309,
    "numberval12": -5e+320,
    "numberval13": -2.225e-308,
    "numberval14": -2.225e-309,
    "numberval15": -3e-320,
    "numberval16": -5e-324,
    "numberval17": -5e-325,
    "numberval18": -7e-350
}`;

let numParsedObj = JSON.parse(numStr);
print(numParsedObj.numberval1);// DBL_MAX, 1.79e+308
print(numParsedObj.numberval2);// greater than DBL_MAX, expect Infinity
print(numParsedObj.numberval3);// greater than DBL_MAX, expect Infinity
print(numParsedObj.numberval4);// DBL_MIN, 2.225e-308
print(numParsedObj.numberval5);// less than DBL_MIN, 2.225e-309
print(numParsedObj.numberval6);// less than DBL_MIN, 3e-320
print(numParsedObj.numberval7);// Number.MIN_VALUE, 5e-324
print(numParsedObj.numberval8);// less than Number.MIN_VALUE, expect 0
print(numParsedObj.numberval9);// less than Number.MIN_VALUE, expect 0

print(numParsedObj.numberval10); // -1.79e+308
print(numParsedObj.numberval11); // -Infinity
print(numParsedObj.numberval12); // -Infinity
print(numParsedObj.numberval13); // -2.225e-308
print(numParsedObj.numberval14); // -2.225e-309
print(numParsedObj.numberval15); // -3e-320
print(numParsedObj.numberval16); // -5e-324
print(numParsedObj.numberval17); // -0
print(numParsedObj.numberval18); // -0

print(Object.is(numParsedObj.numberval2, numParsedObj.numberval11)) // false
print(Object.is(numParsedObj.numberval18, numParsedObj.numberval9)) // false

print(Object.is(numParsedObj.numberval1, 1.79e+308));             // true
print(Object.is(numParsedObj.numberval2, Infinity));              // true
print(Object.is(numParsedObj.numberval3, Infinity));              // true
print(Object.is(numParsedObj.numberval4, 2.225e-308));            // true
print(Object.is(numParsedObj.numberval5, 2.225e-309));            // true
print(Object.is(numParsedObj.numberval6, 3e-320));                // true
print(Object.is(numParsedObj.numberval7, Number.MIN_VALUE));      // true
print(Object.is(numParsedObj.numberval8, 0));                     // true
print(Object.is(numParsedObj.numberval9, 0));                     // true

print(Object.is(numParsedObj.numberval10, -1.79e+308));     // true
print(Object.is(numParsedObj.numberval11, -Infinity));      // true
print(Object.is(numParsedObj.numberval12, -Infinity));      // true
print(Object.is(numParsedObj.numberval13, -2.225e-308));    // true
print(Object.is(numParsedObj.numberval14, -2.225e-309));    // true
print(Object.is(numParsedObj.numberval15, -3e-320));        // true
print(Object.is(numParsedObj.numberval16, -5e-324));        // true
print(Object.is(numParsedObj.numberval17, -0));             // true, distinguishes from 0
print(Object.is(numParsedObj.numberval18, -0));             // true