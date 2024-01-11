/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class Constants {
    static readonly prop11: number = 1;
    private prop22: string = 'hello';
    method33() {
        return 1;
    }
}
export { Constants as BrowserConstants }

class Constants2 {
    static readonly prop11: number = 1;
    private prop22: string = 'hello';
    method33() {
        return 1;
    }
}

class Constants3 {
}
class Constants4 {
}
class Constants5 {
}
export { Constants2, Constants3, Constants4 as Constants4Alias, Constants5}
export function fifoCall1() {
    return 1 + 1;
}

export function fifoCall2() {
    return 1 + 1;
}

export { Constants6, Constants7 as Constants7Alias}