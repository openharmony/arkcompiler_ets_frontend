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

class A {
    s: string;
    b: boolean = false;
}

let a = new A();
let aExists: boolean = !!a;

if (a) { }
if (a.s) { }
if (a.b) { }
if (aExists) { }

if ((a) && (a.s) && a.b && aExists) { }
if (a.s || a.b) { }
if (a || aExists) { }
if (!a || !(a.s) || !a.b || !aExists) { }

while (a) { break; }
while (a.s) { break; }
while (a.b) { break; }
while (aExists) { break; }

do { break; } while (a);
do { break; } while (a.s);
do { break; } while (a.b);
do { break; } while (aExists);

for (let x = 0; a; x++) { if (x > 5) break; }
for (let x = 0; a.s; x++) { if (x > 5) break; }
for (let x = 0; a.b; x++) { if (x > 5) break; }
for (let x = 0; aExists; x++) { if (x > 5) break; }

let x = a ? 1 : 2;
x = (a.s) ? 3 : 4;
x = a.b ? 5 : 6;
x = (aExists) ? 5 : 6;