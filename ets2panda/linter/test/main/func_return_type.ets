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

function q(x: number) { // Need fix
  return w(x)
}
function w(x: number) {
  return x; 			
}

function e(x: string) { // Need fix
  return r(x)
}
function r(x: string) {
  return t(x);
}
function t(x: string): string {
  return x;
}

function y() { // Need fix
  return u();
}
function u() {
  return [1, 2, 3];
}

function f(x: number) { // Not fixable
  if (x <= 0) {
    return x;
  }
  return g(x);
}
function g(x: number) { // Not fixable
  return f(x - 1);
}

function h(x: number, y: number) {
  return x + y;
}

function x() { // Not fixable
  return z(1);
}
function z(a: any) { // Not fixable
  return a;
}

function functionExpressions() {
  let f1 = function (c: C) { // Need fix
    return f2(c);
  };
  let f2 = function (c: C) {
    return new C();
  };
  
  let f3 = function (x: number, y: number) {
    return x + y;
  };

  let f4 = function () { // Need fix
    return f5();
  };
  let f5 = function () {
    return new Map<string, number>();
  };

  let f6 = function () { // Not fixable
    return z(0);
  };
}

function lambdas<T>() {
  let l1 = (t: T) => { // Need fix
    return l2(t);
  };
  let l2 = (t: T) => {
    return t;
  };
  
  let l3 = (x: number, y: number) => {
    return x + y;
  };

  let l4 = () => { // Need fix
    return l5();
  };
  let l5 = () => {
    return (x: number) => x.toString();
  };

  let l6 = () => { // Not fixable
    return z(-1);
  };
}

class C {
  m(x: number) { // Need fix
    return q(x)
  }
  
  m2(x: number) { // Need fix
    return this.m(x)
  }

  m3(x: number) {
    return 10;
  }
  
  m4() { // Need fix
    return this.m2(20);
  }

  m5() { // Not fixable
    return z(30);
  }
}

function no_space_before_body(x: number){ // Need fix
  return w(x)
}

declare function fooImplicitDeclaration(); // CTE - no type in declaration
function fooImplicitImplementation() {}; // OK - deduces void

interface ImplicitTest {
  bar1(); // CTE - no type in declaration
  bar2(): number; // OK - type is specified explicitly
}

declare class ImplicitTestClass {
  bar1(); // CTE - no type in declaration
  bar2(): number; // OK - type is specified explicitly
}
