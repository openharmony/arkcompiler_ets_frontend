/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

interface I {}

function foo(a: string, b: string, i: I): void {
    switch (a) {
        case '0':
            console.log("0");
            break;
        case b:
            console.log(b);
            break;
    }

    switch (i) {
        case null:
            console.log("null interace");
            break;
    }

    switch (undefined) {
        case console.log(1):
        case console.log(2):
            void console.log(3);
    }

    let x = 10, y = 20, z = 30;
    let foo = (n: number) => n;
    switch (x) {
        case x + y:
            console.log("x + y = " + (x + y));
            break;
        case foo(z):
            console.log("foo(z) = " + foo(z));
            break;
        default:
            console.log("default case");
    }
}