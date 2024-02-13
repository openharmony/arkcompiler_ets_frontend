/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
  constructor(
    public readonly x: number,
    protected y: number,
    private z: number
  ) {}

  foo(): void {
    console.log(this.x + this.y + this.z);
  }
}

const a = new A(1, 2, 3);
console.log(a.x);

class B {
  public f: number = 10;

  constructor(q: number, public w = 'default', e: boolean, private readonly r: number[] = [1, 2, 3]) {
    console.log(q, this.w, e, this.r, this.f);
  }
}

const b = new B(1, '2', true, []);
console.log(b.w);

class C {
  constructor(public a: any) {} // not fixable
}

class D {
  constructor(public a: number, private b: {x: string}) {} // not fixable
}