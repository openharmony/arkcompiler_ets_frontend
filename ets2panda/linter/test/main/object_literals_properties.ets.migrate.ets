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

// Untyped object literals
class GeneratedObjectLiteralClass_1 {
    m() { console.log(1.0); } // Error, fixable
}

let method = new GeneratedObjectLiteralClass_1();

class GeneratedObjectLiteralClass_2 {
    get property() { return 2.0; } // Error, fixable
}

let getMethod = new GeneratedObjectLiteralClass_2();

class GeneratedObjectLiteralClass_3 {
    set property(value: number) {
        console.log(value);
    }
}

let setMethod = new GeneratedObjectLiteralClass_3();

let x: number = 1.0, y = '2', z = true;

interface GeneratedObjectLiteralInterface_1 {
    x: number;
    y: string;
    z: boolean;
}
let shorthand: GeneratedObjectLiteralInterface_1 = {
  x: x, // Error, fixable
  y: y, // Error, fixable
  z: z // Error, fixable
};

let spread = {
  ...shorthand // Error, not fixable
};

class GeneratedObjectLiteralClass_4 {
    a: string;
    b: number;
    c: number[];
    x: number;
    y: string;
    constructor(init: GeneratedObjectLiteralInitInterface_4) {
        this.a = init.a;
        this.b = init.b;
        this.c = init.c;
        this.x = init.x;
        this.y = init.y;
    }
    method() {
        console.log(42.0);
    }
    get property() {
        return 0.0;
    }
    set property(value: number) {
        if (value < 0.0) {
            throw new Error('Bad value');
        }
    }
}

interface GeneratedObjectLiteralInitInterface_4 {
    a: string;
    b: number;
    c: number[];
    x: number;
    y: string;
}

let mixed = new GeneratedObjectLiteralClass_4({
    a: "foo",
    b: 42.0,
    c: [1.0, 2.0, 3.0],
    x: x,
    y: y
});

let x2: number = 1.0, y2: number = 2.0, z2: number = 3.0;
let mixedBad = { // Not fixable
  a: 1.0,
  b: 2.0,
  x2: x2, // Error, fixable
  y2: y2, // Error, fixable
  z2: z2, // Error, fixable
  m() {},
  ...shorthand // Error, not fixable
}

// Typed object literals
interface I {
  m(): void;
}
class GeneratedObjectLiteralClass_5 implements I {
    m() {
        console.log(100.0);
    }
}

let i: I = new GeneratedObjectLiteralClass_5();

class C {
  m(): void {
    console.log(200.0);
  }
}
class GeneratedObjectLiteralClass_6 extends C {
    m(): void {
        console.log(300.0);
    }
}

let c: C = new GeneratedObjectLiteralClass_6();

function foo(c: C) {}
class GeneratedObjectLiteralClass_7 extends C {
    m() { console.log(300.0); } // Fixable
}

foo(new GeneratedObjectLiteralClass_7());

class C2 {
  x2: number = 10.0;
  y2: number = 20.0;
  z2: number = 30.0;

  m() {}
}
class GeneratedObjectLiteralClass_8 extends C2 {
    x2: number;
    y2: number;
    z2: number;
    constructor(init: GeneratedObjectLiteralInitInterface_1) {
        super();
        this.x2 = init.x2;
        this.y2 = init.y2;
        this.z2 = init.z2;
    }
    m() { console.log(1.0); } // Fixable
}

interface GeneratedObjectLiteralInitInterface_1 {
    x2: number;
    y2: number;
    z2: number;
}

let c2: C2 = new GeneratedObjectLiteralClass_8({
    x2: x2,
    y2: y2,
    z2: z2
});

let c22: C2 = {
  x2: x2, // Fixable
  y2: y2, // Fixable
  z2: z2, // Fixable
  m() { console.log(1.0); }, // Not fixable, object has spread property
  ...shorthand // Not fixable
};

class C3 {
  x2: number = 10.0;
  y2: number = 20.0;
  z2: number = 30.0;

  m() {}

  constructor(a: number) {}
}
let c3: C3 = {
  x2: x2, // Fixable
  y2: y2, // Fixable
  z2: z2, // Fixable
  m() { console.log(1.0); } // Not fixable, class type has constructor with parameters
};

function capturesFromLocalScope() {
  let a: number = 1.0, b: number = 2.0;
  let captureLocalVal = {
    m() { // Not fixable, captures local values 'a' and 'b'
      console.log(a, b);
    }
  };

  let captureLocalVal2: C = {
    m(): void { // Not fixable, captures local values 'a' and 'b'
      console.log(a, b);
    }
  };

  interface LocalType {
    a: number;
    b: string;
}
  let localTypeVar: LocalType = { a: 1.0, b: '2' };
  let captureLocalType = {
    m() { // Not fixable, captures value of type `LocalType` declared in local scope
      console.log(localTypeVar);
    }
  };
  let captureLocalType2 = {
    m(x: LocalType) { // Not fixable, `x` references type `LocalType` declared in local scope
      console.log(x);
    }
  };

  class LocalClass { x: number = 1.0 };
  let captureLocalType3 = {
    m() { // Not fixable, references type `LocalClass` declared in local scope
      console.log(new LocalClass());
    }
  };
}

// Method overriding field
class C4 {
  a: number = 0.0;
  b() {};
}
let c4: C4 = { // Not fixable, overrides class method with property of functional type
  a: 1.0,
  b: () => {}
};

class C5 {
  a: number = 0.0;
  b: () => void;
}
let c5: C5 = { // Not fixable, overrides class property with method
  a: 1.0,
  b() {}
};

interface I2 {
  a: number;
  b(): void;
}
let i2: I2 = { // Not fixable, implements method as functional-type property
  a: 1.0,
  b: () => {}
};

interface I3 {
  a: number;
  b: () => void;
}
let ii: I3 = { // Not fixable, implements functional-type property as a method
  a: 1.0,
  b() {}
};

// Inheritance
class Base {
  constructor() {}
}
class Derived extends Base {
  m() {}
}
class GeneratedObjectLiteralClass_9 extends Derived {
    m() { console.log(2.0); }
}

let b: Derived = new GeneratedObjectLiteralClass_9();

class Base2 {
  constructor(a: number) {}
}
class Derived2 extends Base2 {
  m() {}
}
let b2: Derived2 = { // Not fixable, derived class inherits a constructor with parameters from base class
  m() { console.log(2.0); }
};

class Base3 {
  constructor(a: number) {}
}
class Derived3 extends Base3 {
  m() {}

  constructor() {
    super(1.0);
  }
}
class GeneratedObjectLiteralClass_10 extends Derived3 {
    m() { console.log(2.0); }
}

let b3: Derived3 = new GeneratedObjectLiteralClass_10();

interface I4 {
  map: Map<string, string>;
}
let map:Map<string,string> = new Map<string,string>();
let i4: I4 = {map: map};

class C6 {
  map1: Map<string, string> = new Map<string,string>();
}

let map1:Map<string,string> = new Map<string,string>();
let c6: C6 = {map1: map1};

// Namespace typed object literals
namespace X {
  export class C {
    m() {
      console.log("C - 1");
    }
  }

  export interface I {
    m(a: number, b: string): void;
  }
}

class GeneratedObjectLiteralClass_11 extends X.C {
    m() {
        console.log("C - 2");
    }
}

class GeneratedObjectLiteralClass_12 implements X.I {
    m(): void {
        console.log("I");
    }
}

function test() {
  let c: X.C = new GeneratedObjectLiteralClass_11()

  let i: X.I = new GeneratedObjectLiteralClass_12()
}

class FooBarBaz {
    foo?: Map<string, Object>
    bar?: string
}

function baz(fooBar: Map<string, Object>) {
    baz2({fooBar});
}

function baz2(fooBarBaz: FooBarBaz) {
}
