/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
// Global-scoped duplicate declarations
import G0 from 'module';
import { G1 } from 'module';
import A from 'x';
interface A {
  f: number;
}
class A implements A {
  m(); // Not duplicate, method overload
  m(a?: number) {
    if (a) a++;
  } // Not duplicate, method overload
}

namespace A {
  export interface B {
    a: number;
  }
  export class B extends A {}
  export interface C {
    a: number;
  } // Not duplicate, interface C has two merging declarations
}

namespace A {
  export interface B {
    b: string;
  }
  export interface C {
    b: string;
  } // Not duplicate, interface C has two merging declarations
}

import * as B from 'y';
interface B {
  f: number;
}
class B {}

import { C, X as D, E, Y as F } from 'z'; // E and F are not duplicates
interface C {
  f: number;
}
class C extends A implements C {}

function D(): number {
  return 1;
}
interface D {
  f: number;
}

function X(); // Not duplicate, function overload
function X(x?: number) {
  // Not duplicate, function overload
  const ab = new A.B();
}

export function scopeDuplicateDeclarations() {
  // Function-scoped duplicate declarations
  const A = 1000;
  interface A {
    f: number;
  }

  const B = 'Text';
  type B = number[];

  class C {}
  interface C {
    f: number;
  }

  function D(): number {
    return 1;
  }
  type D = number;

  function E(): number {
    return 1;
  }
  interface E {
    f: number;
  }

  // Block-scoped duplicate declarations.
  {
    const A = 54;
    interface A {
      f: number;
    }
  }
}

export function destructuringDuplicates() {
  interface F {
    a: number;
  }
  interface H {
    s: string;
  }
  const [F, G, ...H] = [1, 2, 3, 4, 5];

  interface I {
    b: boolean;
  }
  interface K {
    i: I;
  }
  interface M {
    k: K;
  }
  const {
    I,
    J: {
      K,
      L: [M, N],
      O,
    },
  } = { I: 10, J: { K: 'foo', L: [30, 40], O: 'bar' } };
}

export function switchDuplicates(n: number) {
  switch (n) {
    case 1:
      const XX = 10;
      type XX = number;

      function XY(): number {
        return 1;
      }
      break;
    case 25:
      interface XY {
        f: number;
      }

      function XZ(): number {
        return 1;
      }
      break;
    default:
      type XZ = string[];
      break;
  }
}

class PrivateIdentifiers {
  x: number;
  #x: string;

  y(x: number): number {
    return 10;
  }
  #y(x: number): number {
    return 20;
  }

  z: boolean;
  #z(x: number): number {
    return 30;
  }
}

// namespace to every other type - no error
enum T1 {}
namespace T1 {}

class T2 {}
namespace T2 {}

interface T3 {}
namespace T3 {}

type T4 = T2;
namespace T4 {}

namespace T5 {}
namespace T5 {}

// namespace to variable / function - error
namespace G0 {}
namespace G1 {}

function G3() {}
namespace G3 {}

// declarations merging 
namespace NP1 {} // namespace merging is allowed
namespace NP1 {} // namespace merging is allowed

enum EN1 {}
enum EN1 {}

interface IF1 {}
interface IF1 {}

// variable can't collide with interface, type alias and namespace
const V1: number = 1;
interface V1 {}

const V2: number = 1;
namespace V2 {}

const V3: number = 1;
type V3 = V1;

// function can't collide with interface, type alias and namespace
function F1() {}
interface F1 {}

function F2() {}
namespace F2 {}

function F3() {}
type F3 = V1;

// interface checks
interface IF2 {}
class IF2 {}
