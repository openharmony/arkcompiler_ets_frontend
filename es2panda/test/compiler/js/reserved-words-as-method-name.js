/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

class A {
    break() {
        print("method break")
    }
    case() {
        print("method case")
    }
    catch() {
        print("method catch")
    }
    await() {
        print("method await")
    }
    async() {
        print("method async")
    }
    instanceof() {
        print("method instanceof")
    }
    in() {
        print("method in")
    }
}

let a = new A;
a.break();
a.case();
a.catch();
a.await();
a.async();
a.instanceof();
a.in();
