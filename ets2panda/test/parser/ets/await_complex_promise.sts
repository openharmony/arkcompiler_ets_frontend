/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

function foo1(p: Promise<Promise<string>>): void {
    let result: string = await p;
}

function foo2(p: Promise<Promise<string>|number>): void {
    let result: string|number = await p;
}

function foo3(p: Promise<Promise<string>|Promise<number>>): void {
    let result: string|number = await p;
}

function foo4(p: Promise<null|Promise<string>>): void {
    let result: null|string = await p;
}

type Alias = Promise<string>|number;
function foo5(p: Promise<Alias>): void {
    let result: string|number = await p;
}
