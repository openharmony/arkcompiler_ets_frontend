/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http: //www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

interface I {
    i:int;
    j:string;
}

function foo(i:Partial<I>){
    if(i.i == undefined){
        i.i = 123456789
    }
    if(i.j == undefined){
        i.j = "abcdefghi"
    }
}

function main(){
    let partial1:Partial<I> = {i:1234,j:"abcd"};
    assertEQ(partial1.i, 1234)
    assertEQ(partial1.j, "abcd")
    assertTrue(!(partial1 instanceof I))

    let partial2:Partial<I> = {i:1234};
    assertEQ(partial2.i, 1234)
    assertEQ(partial2.j, undefined)
    assertTrue(!(partial2 instanceof I))

    let partial3:Partial<I> = {};
    assertEQ(partial3.i, undefined)
    assertEQ(partial3.j, undefined)
    assertTrue(!(partial3 instanceof I))

    foo(partial1);
    assertEQ(partial1.i, 1234)
    assertEQ(partial1.j, "abcd")

    foo(partial2);
    assertEQ(partial2.i, 1234)
    assertEQ(partial2.j, "abcdefghi")

    foo(partial3);
    assertEQ(partial3.i, 123456789)
    assertEQ(partial3.j, "abcdefghi")
}
