/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

class Cat {
  name: string;

  constructor();
  constructor(name: string);
  constructor(name?: string) {
    "use sendable"
    this.name = name ?? 'Mi';
  }

  static greet1(): string;
  static greet1(msg?: string): string {
    return msg? msg:'hello';
  }

  greet2(): string;
  greet2(msg?: string): string {
    return msg? `${msg}${this.name}`:'hello Mi';
  }
}

const cat = new Cat('BoBo');

print(Cat.greet1());
print(Cat.greet1('hello cat'));
print(cat.greet2());
print(cat.greet2('hello cat: '));