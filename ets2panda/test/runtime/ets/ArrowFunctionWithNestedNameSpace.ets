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

export namespace BarNameSpace {
    export type Callback = (arg: string) => void

    export namespace FooNameSpace {
        export type Callback2 = (arg: string) => void
    }
}

function foo(arg: BarNameSpace.Callback): void {
    arg('hello');
}

function bar(arg: BarNameSpace.FooNameSpace.Callback2): void {
    arg('goodbye');
}

function main(): void {
    foo((arg) => {
        assertEQ(arg, 'hello');
    });

    bar((arg) => {
        assertEQ(arg, 'goodbye');
    });
}
