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

enum Car {
    big,
    small
}

class Animal {
    public age = 0
}

interface Plug {}

// There is default value
export let car: Car

// No default value
export let animal: Animal
export let mutant: Car | Animal
export let jsvalue: JSValue
export let plug: Plug

console.log(car, animal, mutant, jsvalue, plug)

/* @@? 36:13 Error TypeError: Variable 'car' is used before being assigned. */
/* @@? 36:18 Error TypeError: Variable 'animal' is used before being assigned. */
/* @@? 36:26 Error TypeError: Variable 'mutant' is used before being assigned. */
/* @@? 36:34 Error TypeError: Variable 'jsvalue' is used before being assigned. */
/* @@? 36:43 Error TypeError: Variable 'plug' is used before being assigned. */
