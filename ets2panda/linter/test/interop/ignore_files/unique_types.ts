/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

type SomeType = {
    name: string,
}

enum X {
    a = 0,
    b = '1',
}

type UnionString = "A" | "B";
type TemplateLiteralType = `${UnionString}_id`;

export let objectLiteralType: SomeType;
export let mixedEnumType: X;
export let intersectionType: SomeType & X;
export let templateLiteralType: TemplateLiteralType;

export function tsFunction() {
    throw 123;
};
export let stringType: string;
