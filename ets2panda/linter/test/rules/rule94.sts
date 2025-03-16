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

function* counter(start: number, end: number) {
    for (let i = start; i <= end; i++) {
        yield i
    }
}

for (let num of counter(1, 5)) {
    console.log(num)
}


async function complexNumberProcessing(n : number) : Promise<number> {
    return n
}

async function foo() {
    for (let i = 1; i <= 5; i++) {
        console.log(await complexNumberProcessing(i))
    }
}

foo()
