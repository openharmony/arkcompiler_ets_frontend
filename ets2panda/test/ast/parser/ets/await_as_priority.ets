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

class A{}
class B{}

async function func(): Promise<number[]>{
    let a: number[] = [0, 1];
    return a;
}
async function main() {
    let b: Array<number> = await func();
}
async function func1(): Promise<A | B>{
    let a: A = new A();
    return a;
}
async function main1(){
    let b: B = await func1() as B;
}