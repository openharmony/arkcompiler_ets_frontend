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

import assert = require('assert');

const Cat = "cat";
const Dog = "dog";

class MyPets{
  [Cat] = "tom";
  [Dog] = "spike";

  constructor(public para1 = 1, private para2 = "hello") {
    this.para1 = 5;
  }

  public getPara1(){
    return this.para1;
  }

  public getPara2(){
    return this.para2;
  }
}

const pet = new MyPets();

assert(MyPets[Cat]===undefined);
assert(MyPets[Dog]===undefined);

assert(pet[Cat]==="tom");
assert(pet[Dog]==="spike");

assert.strictEqual(pet.getPara1(), 5);
assert.strictEqual(pet.getPara2(), "hello");
assert.strictEqual(pet.para1, 5);
