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
 
class Pot<T> {
    private v: T
    constructor(v: T) {
        this.v = v
    }
    set(v: T) {
        this.v = v;
        return this;
    }
    get(): T {
        return this.v;
    }
}

function main() {
let p = new Pot<string>("")
let q = new Pot<int>(0)

p.set("a")
assert p.get() == "a"
q.set(1)
assert q.get() == 1
p.set("b").set("c")
assert p.get() == "c"
p = p.set("d")
assert p.get() == "d"
q = q.set(2)
assert q.get() == 2
}