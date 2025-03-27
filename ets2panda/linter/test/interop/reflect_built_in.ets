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

import { foo, bar, safe } from "./oh_modules/reflect_export"
import { safeVersion } from "./oh_modules/reflect_export_safe"

class X {
    a: string = 'hello'
    getName() { return this.a }
}

foo(new X());

class Y {
    prop = 42;
}

bar(new Y());

class Z {
    a: string = 'hello';
    getName() { return this.a; }
}

safe(new Z()); //legal

class A {
    prop = 34;
}

safeVersion(new A()) //legal