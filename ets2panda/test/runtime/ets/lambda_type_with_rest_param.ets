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

let a:(...args:number[])=>number = (...args:number[])=>{
    return args[0]
}
type A = (...args:number[])=>string
function foo(a:(...args:number[])=>string){
    return a(3,4,5)
}

function main(){
    assertEQ(a(1,2,3), 1)
    let func:A = (...args:number[]):string=>{ return "abc"}
    assertEQ(foo(func), "abc")
}

