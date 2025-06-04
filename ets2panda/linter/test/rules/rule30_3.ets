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

class X  {
    public foo: number
    private s: string

    constructor (f: number) {
        this.foo = f
        this.s = ""
    }

    public say(): void {
       console.log("X = ", this.foo)
    }
}

class Y {
    public foo: number

    constructor (f: number) {
        this.foo = f
    }
    public say(): void {
        console.log("Y = ", this.foo)
    }
}

function bar(z: X): void {
    z.say()
}

bar(new X(1))
bar(new Y(2) as X)