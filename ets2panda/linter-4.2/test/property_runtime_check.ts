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
  foo: string;
  bar: any;
}

let a: A = new A();
let b: any = new A();

if (a.foo) {
}
if (a.bar) {
}
if (a.bar.baz) {
}
if (b.foo) {
}
if (b.bar) {
}
if (b.bar.baz) {
}

if (a.foo && a.bar && a.bar.baz && b.foo && b.bar && b.bar.baz) {
}
if (a.foo || a.bar || a.bar.baz || b.foo || b.bar || b.bar.baz) {
}
let foobar: boolean = !a.foo;
foobar = !a.bar;
foobar = !a.bar.baz;
foobar = !b.foo;
foobar = !b.bar;
foobar = !b.bar.baz;

while (a.foo) {
  break;
}
while (a.bar) {
  break;
}
while (a.bar.baz) {
  break;
}
while (b.foo) {
  break;
}
while (b.bar) {
  break;
}
while (b.bar.baz) {
  break;
}

do {
  break;
} while (a.foo);
do {
  break;
} while (a.bar);
do {
  break;
} while (a.bar.baz);
do {
  break;
} while (b.foo);
do {
  break;
} while (b.bar);
do {
  break;
} while (b.bar.baz);

for (let x = 0; a.foo; x++) {
  break;
}
for (let x = 0; a.bar; x++) {
  break;
}
for (let x = 0; a.bar.baz; x++) {
  break;
}
for (let x = 0; b.foo; x++) {
  break;
}
for (let x = 0; b.bar; x++) {
  break;
}
for (let x = 0; b.bar.baz; x++) {
  break;
}

let goo = a.foo ? 1 : 2;
goo = a.bar ? 3 : 4;
goo = a.bar.baz ? 5 : 6;
goo = b.foo ? 7 : 8;
goo = b.bar ? 9 : 10;
goo = b.bar.baz ? 11 : 12;