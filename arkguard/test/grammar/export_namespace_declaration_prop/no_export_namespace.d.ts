/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

declare namespace ns9 {
    function foo9(): void;
    class className9 {
        prop91: number;
        prop92: interName9 | undefined;
    }
    interface interName9 {
    }
}
declare namespace ns10 {
    export function foo10(): void;
    export class className10 {
        prop101: number;
        prop102: interName10 | undefined;
    }
    interface interName10 {
    }
    export {};
}
