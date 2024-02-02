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

type PropDecorator = (target: any, propertyKey: any) => void; 
type PropDecoratorWithCall = PropDecorator & ((val: string) => PropDecorator); 

let Prop: PropDecorator;
let Link: PropDecorator;
let ObjectLink: PropDecorator;
let Consume: PropDecoratorWithCall;
let Provide: PropDecoratorWithCall;
let CustomDialog: PropDecorator = (x, y) => {};

class Decorators {
  @Prop
  p: number;

  @Link
  l: number;

  @ObjectLink
  public ol: number;

  @Consume
  private c: number;

  @Consume('foo')
  c2: number;

  @Provide
  pr: number // Not ok

  @Provide('bar')
  pr2: number; // Not ok

  @Prop
  @Provide
  @Link
  f: number;

  f2: number;

  f3: any;

  f4;
}

class CustomDialogController {
};

@CustomDialog
class A {
  controller: CustomDialogController;
  build() {}
}

class B {
  controller: CustomDialogController;
  build() {}
}
