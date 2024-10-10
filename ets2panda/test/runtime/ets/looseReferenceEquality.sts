/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

function eq(x: Object | null | undefined, y: Object | null | undefined) {
    return x == y;
}

function box<T extends Object>(v: T): Object { return v; }

// NOTE(vpukhov): char included?
function test_numerics() {
    let v: byte = 42;
    const create_set = () =>
        [box<byte>(v), box<short>(v), box<int>(v), box<long>(v),
        box<float>(v), box<double>(v)];

    let arr1 = create_set();
    let arr2 = create_set();

    for (const e1 of arr1) {
        for (const e2 of arr2) {
            assert(eq(e1, e2));
        }
    }
}

// NOTE(vpukhov): the same is applied to float?
// NOTE(vpukhov): char == int overlow?
function test_numeric_precision() {
    const maxsafe = Double.MAX_SAFE_INTEGER as long;
    assert(!eq(maxsafe * 4 + 1, maxsafe * 4));
    assert(eq(maxsafe * 4 + 1, (maxsafe * 4) as double));
}

function main() {
    assert(eq(null, null));
    assert(eq(null, undefined));
    assert(eq(undefined, null));
    assert(eq(undefined, undefined));
    assert(eq("abc", ((a: string, b: string): string => { return a + b })("a", "bc")));
    assert(eq(123n, ((a: bigint, b: bigint): bigint => { return a + b })(120n, 3n)));
    assert(eq(true, true));
    assert(eq(box<int>(123), box<int>(123)));
    assert(eq('a', 'a'));

    assert(!eq(null, false));
    assert(!eq(undefined, false));
    assert(!eq(null, 0));
    assert(!eq(true, false));
    assert(!eq("", 0));
    assert(!eq("", false));
    assert(!eq("abc", "cde"));
    assert(!eq("1", 1));
    assert(!eq(123n, 124n));
    assert(!eq(-123n, 123n));
    assert(!eq('a', 'b'));
    assert(!eq(box<int>(1), box<int>(2)));

    test_numerics();
    test_numeric_precision();
}
