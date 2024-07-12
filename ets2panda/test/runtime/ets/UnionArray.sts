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

class Item {
    public value: int;

    constructor(v: int)
    {
        this.value = v;
    }
}

function main() {
    let objectArray = [];
    let boolArray = [true, false, true];
    let intArray = [1, 2, 99, 100];
    let doubleArray = [1, -2, 1.2, 9.9];
    let stringArray = ["one", "two", "three"];
    let classArray = [new Item(1), new Item(2), new Item(3)];
    let unionArray = [true, 9.99, new Item(9), "success"];

    assert(objectArray instanceof Object[]);
    assert(boolArray instanceof Boolean[]);    
    assert(intArray instanceof number[]);
    assert(doubleArray instanceof number[]);
    assert(stringArray instanceof string[]);
    assert(classArray instanceof Item[]);
    assert(unionArray instanceof (Boolean|Double|Item|String)[]);
}
