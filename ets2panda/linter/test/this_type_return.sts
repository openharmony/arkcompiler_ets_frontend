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

class B {
  foo(): this {
    return this.bar();
  }

  bar(): this {
    return this;
  }

  baz: () => this;

  constructor() {
    this.baz = (): this => {
      return this;
    };
  }
}

class C extends B {
  foo(): this {
    return this;
  }
}

class A {
  x: this;

  constructor() {
    this.x = 5;
  }
}

class D {
  foo(): this {
    let f = (): D => {
      return this;
    };

    let d = (): this => {
      return this;
    };

    for (let i = 0; i < 3; i++) {
      if (i == 0) {
        return this;
      }
      return new D();
    }

    return this;
  }

  bar(): D {
    return this;
  }
}
