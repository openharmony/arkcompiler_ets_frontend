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
    private static instance:A = new A();
        static get():A {
        return A.instance; //
    }
}

class AA {
  public static instance?: number;

  getInstance(): number {
    if (!AA.instance) {
      return 0;
    }
    return AA.instance; // Error
  }
}

class AA1 {
  public static instance : Number | String | Object = "smart cast";
  getInstance(): Number {
    if (!(AA1.instance instanceof Number)) {
      return 0;
    }
    return AA1.instance; // Error
  }
}

class AA2 {
  public instance : Number | String | Object= 'smart cast';
  getInstance(): Number {
    if (!(this.instance instanceof Number)) {
      return 0;
    }
    return this.instance; // Error
  }
}

class AA3 {
  public instance : number | String | Object = 'string';
  getInstance(): number {
    if (this.instance instanceof String) {
      return 0;
    } else if (this.instance instanceof Object) {
      return 1;
    }
    return this.instance; // Error
  }
}

function foo2(str:string){
}
function foo22(str:number|string){
}
function foo(spec :string|number){
  foo2(spec) // Error
}
function foo3(spec :string|number){
 if (typeof spec == "string") {
    foo2(spec) // Error
 }
}
function foo3(spec :string|number){
 if (typeof spec == "string") {
    foo22(spec)
 }
}

const input = true;
if (typeof input === 'boolean') {
} else {
  let result = input as string | number | null;  // Error
}