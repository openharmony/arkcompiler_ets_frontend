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

type Nullish = Object | null | undefined;

class Bad { }
class X { }

function expect_ccexc(fn: () => void) {
    try {
        fn();
        assert false;
    } catch (e: Exception) {
        assert(e instanceof ClassCastException);
    }
}

class G<T> {
    erase(x: Nullish): T { return x as T; }
}
function check_G_Object(x: Nullish) {
    expect_ccexc(() => { new G<Object>().erase(x); })
}
function check_G_X(x: Nullish) {
    expect_ccexc(() => { new G<X>().erase(x); })
}
function test_substitution() {
    //check_G_Object(null);
    //check_G_Object(undefined);
    //check_G_X(null);
    check_G_X(undefined);
    check_G_X(new Object());
    check_G_X(new Bad());
}

class CG<T extends X> {
    pass(x: Nullish) { x as T; }
}
function check_CG_X(x: Nullish) {
    expect_ccexc(() => { new CG<X>().pass(x); })
}
function test_constraint() {
    //check_CG_X(null);
    check_CG_X(undefined);
    check_CG_X(new Object());
    check_CG_X(new Bad());
}

class GG<T> {
    pass(x: Nullish) { x as G<T>; }
}
function check_GG(x: Nullish) {
    expect_ccexc(() => { new GG<X>().pass(x); })
}
function test_basetype() {
    //check_GG(null);
    check_GG(undefined);
    check_GG(new Object());
}

function main() {
    // NOTE(vpukhov): add nullability checks, add union param/constraint tests
    test_substitution();
    test_constraint();
    test_basetype();
}
