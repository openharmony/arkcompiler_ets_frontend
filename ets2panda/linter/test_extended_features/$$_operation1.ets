/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


class A {
    n: number
    s: string
    b: boolean
}

var gN: number = 5
var gS: string = "str"
var gB: boolean = true
var gArray: A[] = [new A(), new A()]

// NOTE: This test was written with following in mind:
// 1. Linter doesn't care about ArkUI internal semantics (e.g. specific relations of decorators)
// 2. It ignores $$ but this should not get in a way of the usual analysis

@Entry
@Component
struct SomeComponent {
    @State componentNum: number = 10
    build() {
        // This should not be reported
        Text($$gS)
        Text($$(new A()).s)
        Text($$gArray[0].s)

        Radio().checked($$gN)
        Radio().checked($$(new A()).n)
        Radio().checked($$gArray[0].n)
        Radio().checked($$componentNum)

        Text("").bindPopup($$gB)
        Text("").bindPopup($$(new A()).b)
        Text("").bindPopup($$gArray[0].b)

        // This instead should be

        Text("").bindPopup($${a: boolean})
        let v1: any = "text"
        Text($$v1)
        Radio().checked($$gArray[0]["n"])
        let v2: unknown = false
        Text("").bindPopup($$v2)
    }
}
