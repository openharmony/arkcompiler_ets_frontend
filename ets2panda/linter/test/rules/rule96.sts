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

class Foo {
    foo: number = 0
    common: string = ""
}

class Bar {
    bar: number = 0
    common: string = ""
}

function isFoo(arg: any): arg is Foo {
    return arg.foo !== undefined
}

function doStuff(arg: Foo | Bar) {
    if (isFoo(arg)) {
        console.log(arg.foo)    // OK
        console.log(arg.bar)    // Compile-time error
    } else {
        console.log(arg.foo)    // Compile-time error
        console.log(arg.bar)    // OK
    }
}

doStuff({ foo: 123, common: '123' })
doStuff({ bar: 123, common: '123' })


function isFoo2(arg: Object): boolean {
    return arg instanceof Foo
}

function doStuff2(arg: Object): void {
    if (isFoo2(arg)) {
        let fooArg = arg as Foo
        console.log(fooArg.foo)     // OK
        console.log(arg.bar)        // Compile-time error
    } else {
        let barArg = arg as Bar
        console.log(arg.foo)        // Compile-time error
        console.log(barArg.bar)     // OK
    }
}

function main(): void {
    doStuff2(new Foo())
    doStuff2(new Bar())
}