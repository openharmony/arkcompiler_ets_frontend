/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

type T = () => void

class A {
    foo?: T
    bar?: Function
}

let a: A = {
    foo: () => {
        console.log("Hello")
    },
    bar: () => {
        console.log("Hello")
    }
}

//======================
class Resource{}

class ContainerModuleItem {
    groupName: string = "";
    moduleName: Resource | null = null;
    atributeList: string[] = [];
}

const FLEX_MODULE: ContainerModuleItem[] = [{
    groupName: GROUP.MAIN_DIRECTION,
    moduleName: "ASF",
    atributeList: [ATTRIBUTE.COLUMN, ATTRIBUTE.ROW, ATTRIBUTE.COLUMN_REVERSE],
}]

const enum ATTRIBUTE {
    ROW = 'Row',
    COLUMN = 'Column',
    COLUMN_REVERSE = 'ColumnReverse'
}

const enum GROUP {
    MAIN_DIRECTION = 'MAIN_DIRECTION'
}

//====================================

class C {
    s: string = ""
    n: number = 0
    l: () => void = () => {}
}

let c : C = {
    s: "foo",
        n: 42,
        l: () => {
            console.log("Hi")
        }
}

c.l()