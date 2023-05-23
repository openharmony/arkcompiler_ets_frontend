/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const assert = require('assert');

export namespace secHello {
  export namespace secWorld {
    export function sayWorld() {
      const instance = new World();
      return instance.sayWorld();
    }

    class World{
      private readonly worldStr;

      constructor() {
        this.worldStr = "world";
      }

      public sayWorld(){
        return this.worldStr;
      }
    }
  }

  assert.strictEqual(secWorld.sayWorld(), "world");

  export class Hello {
    private readonly helloStr;

    constructor() {
      this.helloStr = 'hello';
    }

    public sayHello(){
      return this.helloStr;
    }
  }
  
  function sayHello() {
    
  }

  export const cat = new class{
    private readonly mAge: number;

    constructor() {
      this.mAge = 2;
    }

    getAge(){
      return this.mAge;
    }
  }
}

const hello = new secHello.Hello();

assert.strictEqual(hello.sayHello(), "hello");

assert.strictEqual(secHello.cat.getAge(), 2);
