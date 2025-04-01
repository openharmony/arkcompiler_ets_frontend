/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

type Person = {
    name: string
    age: number
    location: string
}

type QuantumPerson = Omit<Person, "location">

let persons : Record<string, Person> = {
    "Alice": {
        name: "Alice",
        age: 32,
        location: "Shanghai"
    },
    "Bob": {
        name: "Bob",
        age: 48,
        location: "New York"
    }
}
console.log(persons["Bob"].age)
console.log(persons["Rob"].age) // Runtime exception