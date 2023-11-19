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

function test_n(v: Object | null) { return v ? true : false }
function test_u(v: Object | undefined) { return v ? true : false }
function test_nu(v: Object | null | undefined) { return v ? true : false }

function main() {
    assert(test_n({}));
    assert(test_u({}));
    assert(test_nu({}));

    assert(!null);
    if (null) { assert(false) }
    assert(!test_n(null));
    assert(!test_nu(null));

    assert(!undefined);
    if (undefined) { assert(false) }
    assert(!test_u(undefined));
    assert(!test_nu(undefined));
}
