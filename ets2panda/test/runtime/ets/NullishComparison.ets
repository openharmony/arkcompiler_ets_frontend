/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

const vnull = ((): Object | null | undefined => { return null })();
const vundefined = ((): Object | null | undefined => { return undefined })();
const vobject = ((): Object | null | undefined => { return new Object() })();

function main() {
    assertTrue(null === null)
    assertTrue(null !== undefined)
    assertTrue(null !== vobject)
    assertTrue(undefined === undefined)
    assertTrue(undefined !== vobject)
    assertTrue(vobject === vobject)

    assertTrue(vnull === vnull)
    assertTrue(vnull !== vundefined)
    assertTrue(vnull !== vobject)
    assertTrue(vundefined === vundefined)
    assertTrue(vundefined !== vobject)

    assertEQ(null, null)
    assertTrue(null == undefined)
    assertNE(null, vobject)
    assertEQ(undefined, undefined)
    assertNE(undefined, vobject)
    assertEQ(vobject, vobject)

    assertEQ(vnull, vnull)
    assertTrue(vnull == vundefined)
    assertNE(vnull, vobject)
    assertEQ(vundefined, vundefined)
    assertNE(vundefined, vobject)
}
