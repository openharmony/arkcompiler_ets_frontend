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
 */1q

class MyClassA {

}

class MyClassB {

}

function getClass1 {
    let a = new MyClassA()

    if (1 > 0) {
        return new MyClassB()
    } else {
        return a
    }
}

function getClass2 {
    if (1 > 0) {
        return 1
    } else {
        return new MyClassA()
    }
}

let para: Record<string, number> = { 'PropA': 47 }
let storage: LocalStorage = new LocalStorage(para)
let prop1 = storage.setAndProp('PropA', getClass1())
let prop2 = storage.setAndProp('PropA', getClass2())
let prop3 = storage.setAndProp('PropA', {name: "jack", age: 2})
let prop4 = storage.setAndProp('PropA', 1 > 0 ? 1 : getClass1())
let prop5 = storage.setAndProp('PropA', 1 > 0 ? {name: "jack"} : "test")
let prop6 = storage.setAndProp('PropA', new MyClassA())
let prop7 = storage.setAndProp('PropA', 1)
let prop8 = storage.setAndProp('PropA', "test")
let prop9 = storage.setAndProp('PropA', true)

@Entry
@Component
struct MyComponent {
    build() {
    }
}