/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

function tag1(strings: TemplateStringsArray): void {
    console.log(strings);
}
function tag2(strings: TemplateStringsArray, val: any): void {
    console.log(strings, val);
}
function tag3(strings: TemplateStringsArray, ...values: any[]): void {
    console.log(strings, values);
}
function recursive(strings: TemplateStringsArray, ...values: any[]): typeof recursive {
    console.log(strings, values);
    return recursive;
}

function main(args: string[]) {
    tag1`Birds are singing`;
    tag2`Welcome, ${args[0]}`;
    tag3`Flowers are blooming`;
    tag3`This product costs ${args[1]} per month`

    recursive`Hello``World`;

    new Function("console.log(arguments)")`Hello`;
}
