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

const empty = function () {};

const multiply = function (x: number, y): number {
  return x * y;
};

function createFunc(): () => number {
  return function () {
    return 100;
  };
}

const foobar = (function () {
  return 'get result immediately';
})();

(function () {
  console.log('foo!');
})();

void (function () {
  console.log('bar!');
})();

const array = [1, 2, 3, 4, 5, 6];
const double = array.map(function (e) {
  return e * 2;
});
const even = array.filter(function (x) {
  return x % 2 === 0;
});

const retTypeInfer = function (p: any) {
  return p;
};

const generator = function * () {
  yield 1;
};

const generic = function <T, E>(t: T, e: E) {
  return t;
};

const asyncFun = async function() {
  console.log('baz!');
};

const factorial = function f(n: number): number {
  return n == 1 ? 1 : n * f(n - 1);
};

class C {
  m() {}
}
const noRecursiveCall = function f(p: () => number): void { // Doesn't have recursive call, should be autofixable
  let a = factorial(3);
  let b = p();
  let c = new C()
  c.m();
};

let iife = function() {
  console.log('called immediately');
}();

let indexAccess = function() {
  console.log('index access');
}[0];

void function() {
  console.log('void');
};

async function awaitFun() { 
  await function() {
    console.log('async');
  };
}

let typeofFunc = typeof function() {
  console.log('typeof');
}

class BindFuncExpr {
  foo() {
    let bar = function(p: boolean) {
      console.log('Function.bind(this)');
    }.bind(this);
  }
}

let callback = function() { console.log('callback'); }
callback = callback || function() { console.log('expr || function(){}'); };

let ternaryExpr = !!callback
  ? function() { console.log('ternary 1'); } || 2
  : 3 && function() { console.log('ternary 2'); };