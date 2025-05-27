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

const empty = () => { };

const multiply = (x: number, y): number => {
    return x * y;
};

function createFunc(): () => number {
  return () => {
    return 100;
};
}

const foobar = (() => {
    return 'get result immediately';
})();

(() => {
    console.log('foo!');
})();

void (() => {
    console.log('bar!');
})();

const array = [1, 2, 3, 4, 5, 6];
const double = array.map((e) => {
    return e * 2;
});
const even = array.filter((x) => {
    return x % 2 === 0;
});

const retTypeInfer = function (p: any) {
  return p;
};

const generator = function * () {
  yield 1;
};

const generic = <T, E>(t: T, e: E) => {
    return t;
};

const asyncFun = async () => {
    console.log('baz!');
};

const factorial = function f(n: number): number {
  return n == 1 ? 1 : n * f(n - 1);
};

class C {
  m() {}
}
const noRecursiveCall = (p: () => number): void => {
    let a = factorial(3);
    let b = p();
    let c = new C();
    c.m();
};

let iife = (() => {
    console.log('called immediately');
})();

let indexAccess = (() => {
    console.log('index access');
})[0];

void (() => {
    console.log('void');
});

async function awaitFun() { 
  await (() => {
    console.log('async');
});
}

let typeofFunc = typeof (() => {
    console.log('typeof');
})

class BindFuncExpr {
  foo() {
    let bar = ((p: boolean) => {
    console.log('Function.bind(this)');
}).bind(this);
  }
}

let callback = () => { console.log('callback'); }
callback = callback || (() => { console.log('expr || function(){}'); });

let ternaryExpr = !!callback
  ? (() => { console.log('ternary 1'); }) || 2
  : 3 && (() => { console.log('ternary 2'); });