/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

function f(shouldInitialize: boolean) {
    if (shouldInitialize) {
       var x = 10
    }
    return x
}

console.log(f(true))
console.log(f(false))

let upper_let = 0
{
    var scoped_var = 0
    let scoped_let = 0
    upper_let = 5
}
scoped_var = 5
scoped_let = 5