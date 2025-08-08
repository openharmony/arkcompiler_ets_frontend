/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

type FuncType = (p: string) => void;

 let f1: FuncType = p => {
    return 0;
 }

 let f2: FuncType = (p: string): void => {
    ((p) => {
        return 0;
    })(p);
 }

 f1 = (p: string): number => {
    return 0;
 }

 f2 = (p: string): void => {
    ((p: string): number => {
        return 0;
    })(p);
 }

 let f3: (p: string) => number = p => {
    return 0;
 }

 f1 = f3;

 f2 = (p: string): void => {
    f3(p);
 };

 type FuncType2 = (p: string) => number;

 let f4 : FuncType | FuncType2 = p => {
    return 0;
 }

 type FuncType3 = (p:string, q:string) => void

 let f5: FuncType3 = (p, q) => {
    return 0;
 }

 f5 = (p:string, q:string):number => {
    return 0;
 } 

type FuncTypeWithOptionalParam = (p?: string, q: number = 0) => void;

let f6: FuncTypeWithOptionalParam = (p, q) => {
    return 0;
};

type BaseType = (p: string) => number;
type WrappedType = BaseType;
type FinalType = WrappedType;

let f7: FinalType = (p) => {
    return 0; 
}

type FuncTypeNoParams = () => void;

let fNoParams: FuncTypeNoParams = () => {
    return 0;
};

class A {}

class C extends Array<A> {}

class B {
  private arr: Array<A> = [];

  test(): C {
    return this.arr;
  }
}

function sleep(time: number): Promise<Object> {
  return new Promise<Object>((resolve) => setTimeout(resolve, time));
}
sleep(100);

const caseName = 'PromiseAnyTest0200';
console.info(`${caseName} test start`);
const startTime = Date.now();
const promises: Promise<Object>[] = [];
const totalPromises = 1000;
const delay = 100;
for (let i = 0; i < totalPromises; i++) {
  promises.push(
    new Promise<string>((_, reject) =>
      setTimeout(() => {
        reject(new Error(`Failure ${i}`));
      }, delay)
    )
  );
}

class D {
  fun(a: ArrayBufferLike): ArrayBuffer {
    return a;
  }
}

class X {
  n: number = 0
  s: string = ''
}

class Y {
  n: number = 0
  s: string = ''
}

class E {
  Dfun(a: X|Y): X {
    return a;
  }
}