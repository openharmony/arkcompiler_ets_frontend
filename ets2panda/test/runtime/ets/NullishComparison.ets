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

const vnull = ((): Object | null | undefined => { return null })();
const vundefined = ((): Object | null | undefined => { return undefined })();
const vobject = ((): Object | null | undefined => { return new Object() })();

function main() {
    assert(null === null);
    // assert(null !== undefined); // not compatible
    assert(null !== vobject);
    assert(undefined === undefined);
    assert(undefined !== vobject);
    assert(vobject === vobject);

    assert(vnull === vnull);
    assert(vnull !== vundefined);
    assert(vnull !== vobject);
    assert(vundefined === vundefined);
    assert(vundefined !== vobject);

    assert(null == null);
    assert(null == undefined);
    assert(null != vobject);
    assert(undefined == undefined);
    assert(undefined != vobject);
    assert(vobject == vobject);

    assert(vnull == vnull);
    assert(vnull == vundefined);
    assert(vnull != vobject);
    assert(vundefined == vundefined);
    assert(vundefined != vobject);
}
