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

import { Country } from './test1'
import type { Color } from './test2'

const enum City {
    BEIJING = 'beijing',
    SHANGHAI = 'shanghai',
};

interface Position {};

class Person {
    name: string;
    private age: number;
    mother: Person;
    father: Person;
    num: bigint;
    child: Person | null;
    country: Country;
    city: City;
    pos: Position;
    mix: Country | City | Position;
    hair: Color;
    constructor() {
        "use sendable";
    }
}

function Test() {
    class Pet<T, U> {
        name: string;
        color: T | undefined;
        weight: U;
        constructor() {
            "use sendable";
        }
    }
}