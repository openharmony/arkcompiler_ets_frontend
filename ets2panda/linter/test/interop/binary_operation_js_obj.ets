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
import {foo,m,n} from "./binary_operation_js_obj_js"
let a = foo.a
let b = foo.b
a + b
a - b
a * b
a / b
a % b
a ** b

m + n
m % n
m ** n

let x = 1, y = 2;
x + y;
x - y;
x % y;
x ** y;

let bar = { a: 1, b: 2 };

let x2 = bar.a, y2 = bar.b;
x2 + y2;
x2 - y2;
x2 % y2;
x2 ** y2;

foo.a + foo.b;