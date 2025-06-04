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

import {
    I,
    foo,
    I2,
    I3,
    bar,
    C,
    getDynamicObject,
    dynamic_array,
    padding,
    margin,
    position,
    IndexedSignatureType,
    postCardAction
} from "./dynamic_lib"

function main(): void {
    let obj: I = {
        f1: {a: 10, b: 20},
        f2: [{c: 30}, {d: 40}],
        "prop.xxx": 0
    }

    obj = {
        f1: {e: "abc"},
        f2: [{g: 50}]
    }

    obj.f1 = {f: 100}
    obj.f1 = [{a1: 1}, {a2: 2, a3: 3}]

    foo({f2: 'abc', f3: 30})
    foo([{b1: 1, b2: 2}, {b3: '3'}])

    let obj2: I2 = {
        f1: {a: 10, b: 20},
        f2: [{c: 30}, {d: 40}],
        f3: {a: '11', b: 444, c: {f: {d: [1, 2]}}}
    }
    
    bar({f2: 'abc', f3: 30})
    bar([{b1: 1, b2: 2}, {b3: '3'}], {c: 4, d: 5})

    let obj3: I3 = {
        f1: {a: 10, b: 20},
        f2: {a: '11', b: 444, c: {f: {d: [1, 2]}}},
        f3: [{c: 30}, {d: 40}]
    }
}

// #13412 - assign dynamic object (interop) to some static type from standard library
interface InitProps {
    p?: number;
    q?: Record<string, Object> | undefined;
    r?: Object | undefined | Record<string, Object>;
}
function createInitProps(c: C) {
    let a: InitProps = {
        p: c.a,
        q: c.b
    }

    let b: InitProps = {
        r: getDynamicObject()
    }
}

// #13483 - pass object literal to method call of exported variable
dynamic_array.splice(2, 0, {a: 1, b: '2'});

// #13550 - allow literals as property names in dynamic context
padding({'top': '0px', 'right': '5px', 'bottom': '10px', 'left': '15px'});
margin({'top': '10px', 'right': '20px', 'bottom': '30px', 'left': '40px'});
position({'x': '20', 'y': '40'});

// allow literal as property name for type aliases that come from interop
function typeAliasLitAsPropName(): IndexedSignatureType {
    return {
        'a': '1',
        'b': '2',
        'c': '3'
    }
}

// #14399
postCardAction({}, {
    "action": 'router',
    "abilityName": 'SomeAbility',
    "params": {
        "message": 'add detail'
    }
});