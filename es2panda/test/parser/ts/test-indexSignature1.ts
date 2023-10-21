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


type a = symbol;

namespace ns {
    export type a = string
}

interface I1 {
    [k1: string]: boolean;
    [k2: number]: boolean;
    [k3: symbol]: boolean;
    [k4: `templateLiteral-${string}`]: boolean;
}

interface I2 {
    [k1: number | ns.a | a]: boolean;
}

class A {
    [k1: string | number | symbol | `templateLiteral-${string}`]: boolean;
}

const x: { [k: string | number | symbol | `templateLiteral-${string}`]: boolean } = {};
