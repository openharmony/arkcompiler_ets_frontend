/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

let res: int
type F = () => void;

function bar() :void {
    return;
}

function foo(f: F): void {
    return Void;
}

function emptyfoo(): void {
}

function noreturnfoo(): void {
    let a = 2;
}

function main(): int {

    let instance = Void;
    let static_field = void.void_instance;

    let a = foo(bar);
    let b = bar();
    let c = console.print("");
    let d = emptyfoo();
    let e = noreturnfoo();

    assert(instance === static_field);
    assert(instance === a);
    assert(instance === b);
    assert(instance === c);
    assert(instance === d);
    assert(instance === e);

    return 0;
}
