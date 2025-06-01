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

class A {}

class G {}

class B {
  static a: A
}

class C {
  static g: G
}

const c = new C();

class D {
  static a: A | undefined = undefined
  static g: G;
}

class F {
  static a: A 
  static g: G | undefined = undefined;
}

const f = new F();

@Entry
@Component
struct Index {
  @State message: string = 'Hello World';
  public static abc:string ;

  build() {
      Text(this.message)
      .height('100%')
      .width('100%')
  }
}