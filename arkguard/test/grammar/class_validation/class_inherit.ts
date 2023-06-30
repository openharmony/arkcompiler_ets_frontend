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

class Animal {
  name: string;

  constructor(theName: string) {
    this.name = theName;
  }

  move(distanceInMeters: number = 0, mode: string): string {
    return `${this.name} ${mode} ${distanceInMeters}m.`;
  }
}

class Dog extends Animal {
  constructor(name: string) {
    super(name);
  }

  move(distanceInMeters = 5, mode: string): string {
    console.log('Slithering...');
    return super.move(distanceInMeters, mode);
  }

  bark(): string {
    return 'Woof! Woof!';
  }
}

const dog = new Dog('dog');

assert(dog.bark() === 'Woof! Woof!', 'success');

assert(dog.move(10, 'run') === 'dog run 10m.', 'success');
