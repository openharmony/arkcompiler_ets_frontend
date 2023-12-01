/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

class A {
    async testAsyncVoidMethodImplicit() {}
    async testAsyncVoidMethodExplicit(): Promise<void> { return }
    async testAsyncVoidMethodExplicitObject(): Promise<void> { return Void }
    async testAsyncVoidMethodReturns() {
        let flag = false
        if (flag) {
            return
        } else {
            if (flag) { return }
        }
    }
}

async function testAsyncVoidImplicit() {}
async function testAsyncVoidExplicit(): Promise<void> { return }
async function testAsyncVoidExplicitObject(): Promise<void> { return Void }
async function testAsyncVoidEarlyReturn(): Promise<void> {
    let flag: boolean = true
    if (flag) {
        return
    }
    console.println("something")
}
async function testAsyncVoidMultipleReturns() {
    let flag: boolean = true
    if (flag) {
        return
    }
    console.println("something x1")
    if (!flag) {
        return // we return here
    }
    console.println("something x2")
    return console.println("something x3")
}

// NOTE(orlovskiymaxim): add support for lambdas
// let testAsyncVoidLambdaImplicit = async () => {}
// let testAsyncVoidLambdaExplicit = async (): Promise<void> => { return }
// let testAsyncVoidLambdaExplicitObject = async (): Promise<void> => { return }
