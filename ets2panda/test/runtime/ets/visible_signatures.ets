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

class A {
    foo(a: Double | undefined): Int {
        return 1;
    }
    private foo(a: double): Int {
        return 0;
    }

    foo2(a: Int | undefined): Int {
        return 1;
    }
    private foo2(a: int): Int {
        return 0;
    }

    foo3(a: Number | undefined): Int {
        return 1;
    }
    private foo3(a: number): Int {
        return 0;
    }

    foo4(a: Number | undefined): Int {
        return 1;
    }
    protected foo4(a: number): Int {
        return 0;
    }

}

function main(): void {
    assert( new A().foo(3.0) == 1)
    assert( new A().foo2(3) == 1)
    assert( new A().foo3(3.0) == 1)
    assert( new A().foo4(3.0) == 1)
}
