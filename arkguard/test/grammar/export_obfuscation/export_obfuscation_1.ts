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

export class PersonClass01 {
    name:string;
    age:number;
}

export function foo01(para01: number, para02: number) {
    const v1 = 1;
    const v2 = 2;
    return para01 + para02 + v1 + v2;
}

function foo02(para03: string, para04: number){
    const v1 = 4;
    const v2 = 5;
    return para03 + para04.toString();
}