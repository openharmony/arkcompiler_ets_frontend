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


@Sendable // OK
class SendableClass7 {
    prop: string; // OK

    constructor() {} // OK

    myMethod1() {} // OK

    myMethod2(param: string) {} // OK
  
    get myProperty(): string { // OK
      return this.prop;
    }
    set myProperty(value: string) { // OK
      this.prop = value;
    }
}

@NonSendable // ERROR, only `@Sendable` can be used on a sendable class declaration
@Sendable
class SendableClass8 {
    @SomeDecorator // ERROR, no decorators can be used in a sendable class
    prop: string;

    constructor() {}

    @SomeDecorator // ERROR, no decorators can be used in a sendable class
    myMethod1() {}

    myMethod2(@SomeDecorator param: string) {} // ERROR, no decorators can be used in a sendable class
  
    @SomeDecorator // ERROR, no decorators can be used in a sendable class
    get myProperty(): string {
      return this.prop;
    }
    @SomeDecorator // ERROR, no decorators can be used in a sendable class
    set myProperty(value: string) {
      this.prop = value;
    }
}