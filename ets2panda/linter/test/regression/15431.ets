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

class C1 {
  static a: number = 1;

  static {
  }

  static { // should report error `arkts-no-multiple-static-blocks`
  }
}

class C2 {
  static a: number = 1;

  static {
    this.a; // should report error arkts-no-standalone-this
  }
}

class C3 {
  static a: number = 1;

  static {
    class C3 {
    }
  }

  static { // should report error
  }
}

class C4 {
  static a: number = 1;

  static f() {
    class C4 {
      static {
      }
    }
  }

  static { // shouldn't report error
  }
}