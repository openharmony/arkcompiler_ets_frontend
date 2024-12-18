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

// test const enum inside namespace 
namespace ns {
    export const enum Enum {
        ONE,
        TWO
    }

    export class A {
        constructor() {
            "use sendable";
        }
        prop1: Enum = 0;
        static prop2: Enum1 = 1;
    }

    const enum Enum1 {
        ONE,
        TWO
    }
    
    
    namespace ns1 {
        export class A {
            constructor() {
                "use sendable";
            }
            prop1: Enum = 0;
            static prop2: Enum1 = 1;
        }
    }

    print(ns1.A.prop2);
    print(new ns1.A().prop1);
}

print(ns.A.prop2)
print(new ns.A().prop1)

// test merged namespaces
namespace ns_1 {
    export class A{
        constructor() {
            "use sendable";
        }
        static prop1: Enum = 0
        prop2: Enum = 1
    }
}

namespace ns_1 {
    export const enum Enum {
        ONE,
        TWO
    } 
}

print(ns_1.A.prop1)
print(new ns_1.A().prop2)

// test merged enum and namespace
namespace ns_2 {
    namespace Enum {}
    export const enum Enum {
        ONE,
        TWO
    }

    export class A{
        constructor() {
            "use sendable";
        }
        static prop1: Enum = 0
        prop2: Enum = 1
    }
}

print(ns_2.A.prop1)
print(new ns_2.A().prop2)