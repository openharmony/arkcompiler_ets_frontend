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

export interface RA<T> {
    each: ()=> void
}

export function Repeat<T>(style: ((instance: RA<T>) => void) | undefined) {
    if (style != undefined) {
        let a : RA<T> = { each: ()=>{} }
        style(a);
    }
}

function main() {
    let count = 0;
    Repeat<string>((instance) => {
        instance.each()
        count++;
    });
    assertEQ(count, 1)
}
