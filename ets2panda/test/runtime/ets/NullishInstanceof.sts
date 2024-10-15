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

function is_null(v: Object | null | undefined) {
    return v instanceof null;
}

function is_obj(v: Object | null | undefined) {
    return v instanceof Object;
}

class Foo { };

type nullish_obj = Object | null | undefined;
type nullish_int = Int | null | undefined;
type nullish_foo = Foo | null | undefined;

function is_nullish_obj(v: nullish_obj) {
    return v instanceof nullish_obj;
}

function is_nullish_int(v: nullish_int) {
    return v instanceof nullish_int;
}

function is_nullish_foo(v: nullish_foo) {
    return v instanceof nullish_foo;
}

function is_nullish_foo_erased(v: nullish_obj) {
    return v instanceof nullish_foo;
}

function main() {
    const obj = new Object();
    const foo = new Foo();
    const boxint = new Int(3);

    assert(is_null(null) == true);
    assert(is_null(undefined) == false);
    assert(is_null(obj) == false);

    assert(is_obj(null) == false);
    assert(is_obj(undefined) == false);
    assert(is_obj(obj) == true);

    assert(is_nullish_obj(null) == true);
    assert(is_nullish_obj(undefined) == true);
    assert(is_nullish_obj(obj) == true);
    assert(is_nullish_obj(foo) == true);

    assert(is_nullish_int(null) == true);
    assert(is_nullish_int(undefined) == true);
    assert(is_nullish_int(boxint) == true);

    assert(is_nullish_foo(null) == true);
    assert(is_nullish_foo(undefined) == true);
    assert(is_nullish_foo(foo) == true);

    assert(is_nullish_foo_erased(null) == true);
    assert(is_nullish_foo_erased(undefined) == true);
    assert(is_nullish_foo_erased(obj) == false);
    assert(is_nullish_foo_erased(boxint) == false);
    assert(is_nullish_foo_erased(foo) == true);
}
