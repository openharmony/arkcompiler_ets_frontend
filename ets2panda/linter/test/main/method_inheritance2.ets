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

class A {
  a: number = 0
}
class B {
  a: number = 0
}
class C {
  a: number = 0
}

class D extends A{
  a: number = 0;
  b: number = 1;
}


// T
class Base3<T> {
  foo<T>(obj: A | B): void {
    console.log("base")
  }
  foo2<T>(obj: A | B): void {
    console.log("base")
  }
  foo3<T>(obj: A | B | C): void {
    console.log("base")
  }
}
// T extends
class Derived3<T> extends Base3<T> {
  foo<T>(obj: A): void {      // (arkts-method-inherit-rule) error
    console.log("Derived:" + obj.a)
  }
  foo2<T>(): void {   // (arkts-method-inherit-rule) error
    console.log("Derived:")
  }
  foo3<T>(obj: A | B): void {   //(arkts-method-inherit-rule) error
    console.log("Derived:")
  }
}

// T interface
interface  BaseI2<T> {
  foo<T>(obj: A | B):void;
  foo2<T>(obj: A ): void;
  foo3<T>(obj: A | B | C): void;
}

// T implements
class DerivedI2<T> implements BaseI2<T> {
  foo<T>(obj: A): void {
    console.log("Drived");  // (arkts-method-inherit-rule)  error
  }
  foo2<T>(): void {
    console.log("Drived");  // (arkts-method-inherit-rule) error
  }
  foo3<T>(obj: A | B): void {
    console.log("Drived");  // (arkts-method-inherit-rule) error
  }
}

class Base5 {
  public foo(): A|B {
    console.log("base")
    return new A();
  }
  static foo2(){
    console.log("base")
    // return new A();
  }
  async foo3():  Promise<A> {
    console.log("base")
    return new A();
  }
  static foo4():void{
    console.log("base")
    // return new A();
  }
}

// extends
class Derived5 extends Base5 {
  public foo(): A|B|C{      //  (arkts-method-inherit-rule)
    console.log("Derived:")
    return new A();
  }

  static foo2(): A{      //  (arkts-method-inherit-rule) error
    console.log("Derived:")
    return new A();
  }

  async foo3(): Promise<A|B> {   //  (arkts-method-inherit-rule)
    console.log("Derived:")
    return new A();
  }
  static foo4(): A{      //  (arkts-method-inherit-rule)  error
    console.log("Derived:")
    return new A();
  }
}

interface I{
  pp(key:string,value:string):void
  pp(key:string):void
}

class J implements I{
  pp(key: string,value?:string):void {  // 漏报arkts-method-inherit-rule
  }
}