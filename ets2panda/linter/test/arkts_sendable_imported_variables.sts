/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

@Sendable
class SendableClassA {
    a: number = 1;
}

@Sendable
class SendableClassB {
    b: SendableClassA = new SendableClassA();
}

@Sendable
class SendableClassC {
    static a: number = 1;
}

@Sendable
class SendableClassD {
    b: number = SendableClassC.a;
}

@Sendable
class SendableClassE {
  static public a: number = 1;
  f(p: number) {
    @Sendable
    class SendableClassF { 
      public b: number = SendableClassE.a;
    }
  }
}

if (true) {
    @Sendable
    class SendableClassG {
        static a: number = 1;
    }

    @Sendable
    class SendableClassH {
        b: SendableClassG = new SendableClassG(); //ERROR
    }
}

let a: number = 1

@Sendable
class SendableClassI {
    b: number = a; //ERROR
}


@Sendable
class SendableClassJ {
    p: number = 1;
}
let b:SendableClassJ = new SendableClassJ();

@Sendable
class SendableClassK {
    ma: SendableClassJ = b; // ERROR
}