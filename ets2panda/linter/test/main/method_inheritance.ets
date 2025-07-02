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

abstract class Y {
    abstract getDataByName(name: string | number, albumUri: string): Promise<void>;
}

class X extends Y {
    async getDataByName(name: string, albumUri: string): Promise<undefined> { // error 2
        return;
    }
}

abstract class B {
    abstract getDataByName(name: string | number, albumUri: string): Promise<undefined> | Promise<void>;
}

class A extends B {
    async getDataByName(name: string | number | boolean, albumUri: string): Promise<undefined> { //Legal
        return undefined;
    }
}

abstract class W {
    abstract getDataByName(name: string | number, albumUri: string): Promise<void>;
}

class Q extends W {
    async getDataByName(name: string | number, albumUri: string | number): Promise<undefined> {// error 1
        return;
    };
}

abstract class BaseClass3 {
    abstract compute(value: string): string;
}

class IncorrectWiderReturn extends BaseClass3 {
    compute(value: string): string | number {// error 1
        return value.length > 5 ? value : 0;
    }
}

abstract class BaseClass4 {
    abstract setValues(x: string | number, y: boolean | number): void;
}

class IncorrectMultipleParamMismatch extends BaseClass4 {
    setValues(x: string, y: boolean): void {// error 2
        console.log(x, y);
    }
}

abstract class BaseClass5 {
    abstract transform(data: number | string): number;
}

class IncorrectBothMismatch extends BaseClass5 {
    transform(data: number): number | string {// error 2
        return data > 10 ? data : "too small";
    }
}

//legal
abstract class BaseClass {
    abstract getData(a: string | number): string | number;
}

class CorrectWiderParam extends BaseClass {
    getData(a: string | number | boolean): string | number {
        return typeof a === 'boolean' ? 0 : a;
    }
}

class CorrectNarrowerReturn extends BaseClass {
    getData(a: string | number): string {
        return typeof a === 'number' ? a.toString() : a;
    }
}

class CorrectBothWiderParamNarrowReturn extends BaseClass {
    getData(a: string | number | boolean): string {
        return String(a);
    }
}


class A1 {
  a: number = 0
}
class B1 {
  a: number = 0
}
class C {
  a: number = 0
}

class Base {
  foo(obj: A1 | B1): void {
    console.log("base")
  }
  foo2(obj: A1 | B1): void {
    console.log("base")
  }
  foo3(obj: A1 | B1 | C): void {
    console.log("base")
  }
}

// extends
class Derived extends Base {
  foo(obj: A1): void {      // error 1
    console.log("Derived:" + obj.a)
  }
  foo2(): void {   // error 1
    console.log("Derived:")
  }
  foo3(obj: A1 | B1): void {   // error 1
    console.log("Derived:")
  }
}

interface  BaseI {
  foo(obj: A1 | B1):void;
  foo2(obj: A1): void;
  foo3(obj: A1 | B1 | C): void;
}

// implements
class Derived2 implements BaseI {
  foo(obj: A1): void {   // error 1
    console.log("Drived");
  }
  foo2(): void {   // error 1
    console.log("Drived");
  }
  foo3(obj: A1 | B1): void {   // error 1
    console.log("Drived");  
  }
}

class Base2 {
  foo(): A1|B1 {
    console.log("base")
    return new A1();
  }
  foo2(){
    console.log("base")
    // return new A();
  }
  foo3():  A1 {
    console.log("base")
    return new A1();
  }
  foo4():void{
    console.log("base")
    // return new A();
  }
}

//extends
class Derived3 extends Base2 {
  foo(): A1|B1|C{      // error 1
    console.log("Derived:")
    return new A1();
  }

  foo2(): A1{      // error 1
    console.log("Derived:")
    return new A1();
  }

  foo3(): A1|B1 {   // error 1
    console.log("Derived:")
    return new A1();
  }
  foo4(): A1{      // error 1
    console.log("Derived:")
    return new A1();
  }
}


interface  Base3 {
  foo(): A1|B1 ;
  foo2(): void;
  foo3(): A1;
}

// implements
class Derived4 implements  Base3 {
  foo(): A1|B1|C{      // error 1
    console.log("Derived:")
    return new A1();
  }

  foo2(): A1{      // error 1
    console.log("Derived:")
    return new A1();
  }

  foo3(): A1|B1 {   // error 1
    console.log("Derived:")
    return new A1();
  }
}

class P {
}

class PP extends P {
  public static toString(result: number): string { // Legal
    return '';
  }
}

class RCP<T = undefined> {}

interface aa {
  aa?: Function;
}
interface bb<T = undefined> extends aa {
    onError(res: RCP<T>): void;
}
class CC implements bb {
  onError(res: RCP): void  {} // Legal
  aa?: Function = () => {}
}
class Animal {}
class Dog extends Animal {}

class Base6 {
  public foo(): Animal {
    console.log("base")
  }
}
// extends
class Derived6 extends Base6 {
  public foo(): Dog {      // no error
    console.log("Derived:")
  }
}