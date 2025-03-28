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

function getFuncWithArgsZero(func: (() => void) | (() => Promise<void>)) {
    return new Promise<void>(async (resolve: (value: PromiseLike<void>) => void) => {
        await (func as () => Promise<void>)();
        const funcStr = (func as object).toString()
        const argsCount = getFunctionArgumentsCount(funcStr)
        const isAsync = checkIsAsyncFunction(funcStr)
        resolve(Promise.resolve());
    });
}

function getFunctionArgumentsCount(funcStr: string): number {
    const regex = new RegExp("^[0123456789]$", "g")
    let count = ""
    for(let str of funcStr) {
        if(regex.test(str)) {
            count = str
        }
    }
    if(count.length) {
        return Number(count)
    }
    return 0
}

function checkIsAsyncFunction(funcStr: string): boolean {
    const endIndex = funcStr.lastIndexOf("):")
    const validStr = funcStr.slice(endIndex)
    if(validStr.indexOf("Promise") !== -1) {
        return true
    } else {
        return false
    }
}


