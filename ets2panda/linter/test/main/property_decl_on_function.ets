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

function foo(path: string): void {
  console.log(path);
}

foo.bar = (path: string): string => {
  return path + ': foo.bar';
};

foo.baz = 1;

foo.bah = { x: 1, y: 2 };

console.log(foo.baz);
console.log(foo.bah);
console.log(foo.name);
console.log(foo.length);
console.log(foo.arguments);
console.log(foo.caller);

// Arrow function
const foo2 = (path: string) => {
  console.log(path);
};

foo2.bar = 2;
console.log(foo2.bar);
console.log(foo2.name);
console.log(foo2.length);
console.log(foo2.arguments);
console.log(foo2.caller);

// Std 'Function' type
const stdFunc: Function  = (path: string) => {
  console.log(path);
};

console.log(stdFunc.name);
console.log(stdFunc.length);
console.log(stdFunc.arguments);
console.log(stdFunc.caller);

// Functional type
type FuncType = (path: string) => void;
let ft: FuncType = (path: string): string => {
  return path + ': foo.bar';
};

console.log(ft.name);
console.log(ft.length);
console.log(ft.caller);

// Functional type alias
type FT2 = FuncType;
let ft2: FT2 = (path: string): string => {
  return path + ': foo.bar';
};

console.log(ft2.name);
console.log(ft2.length);
console.log(ft2.caller);