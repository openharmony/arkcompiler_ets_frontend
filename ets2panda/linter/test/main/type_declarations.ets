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

interface Control {
  state: any;
}

interface SelectableControl extends Control {
  select(): void;
}

enum Mammals {
  Humans = 'Humans',
  Bats = 'Bats',
  Dolphins = 'Dolphins',
}

enum Reptiles {
  Snakes = 'Snakes',
  Alligators = 'Alligators',
  Lizards = 'Lizards',
}

if ('snakes' in Mammals) console.log('?');

type Animal = Mammals | Reptiles;

class Proc {
  private state: any;
  private pipe: number;
  get Pipe() {
    return this.pipe;
  }
  set Pipe(p: number) {
    this.pipe = p;
  }
}

const cntr: Proc = new Proc();
cntr.Pipe = 1;
const pp = cntr.Pipe;

interface ActiveProc extends Proc {
  activate(): void;
}

interface ActiveProc extends Proc {
  deactivate(): void;
}

enum Colors {
  red,
  orange,
  yellow,
}
enum Colors {
  green,
  blue,
  purple,
}

function classExpressionTest() {
  const fooClass = class {
    bar() {
      return 'Hello World!';
    }
  };
  const fooInstance = new fooClass();
  fooInstance.bar();

  const rectangleClass = class {
    constructor(height, width) {
      this.height = height;
      this.width = width;
    }
    area() {
      return this.height * this.width;
    }
  };
  console.log(new rectangleClass(5, 8).area());
}

interface Box {
  contents: any;
}

class BadA implements BadD { }
class BadB extends BadA { }
interface BadD extends BadB { }

class BadE implements BadE { }

class Empty { };

function heritageRecursionTest() {
  let e1: Empty = new BadA();
  let e2: Empty = new BadE();
}
