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
let GeneratedImportVar_1 = ESValue.load('./binary_operation_js_obj_js');
let foo = GeneratedImportVar_1.getProperty('foo');
let m = GeneratedImportVar_1.getProperty('m');
let n = GeneratedImportVar_1.getProperty('n');

let a = foo.getProperty("a")
let b = foo.getProperty("b")
a + b
a - b
a * b
a / b
a % b
Math.pow(a, b)

m.toNumber() + n.toNumber()
m.toNumber() % n.toNumber()
Math.pow(m.toNumber(), n.toNumber())

let x: number = 1.0, y: number = 2.0;
x + y;
x - y;
x % y;
Math.pow(x, y);

interface GeneratedObjectLiteralInterface_1 {
    a: number;
    b: number;
}
let bar: GeneratedObjectLiteralInterface_1 = { a: 1.0, b: 2.0 };

let x2: number = bar.a, y2: number = bar.b;
x2 + y2;
x2 - y2;
x2 % y2;
Math.pow(x2, y2);

foo.getProperty("a").toNumber() + foo.getProperty("b").toNumber();