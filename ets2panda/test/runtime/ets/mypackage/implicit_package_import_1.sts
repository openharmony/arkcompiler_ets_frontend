/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

package mypackage;

function ClassTypeTest(a0: C1){
    assertEQ(C1.stmemb, "c1_stmemb")
    assertEQ(a0.memb, 2)
    assertEQ(a0.bar(), 3)
    assertEQ(a0.baz(), 4)
}

function main(): void {
    ClassTypeTest(new C1());
    let locVar: mytype = new A();
    assertEQ(locVar.aMemb, 5)
    assertEQ(globVar1, 7)
    // NOTE (mmartin): Enable this assert, when correct initialization order of global variables is well defined for packages
    // assertEQ(globVar2, 7)
}

// NOTE (mmartin): Merge these when correct initialization order of global variables is well defined for packages
let globVar2: number;
globVar2 = globVar1;

function func2(a0: number): void {
    assertEQ(a0, 6)
}
