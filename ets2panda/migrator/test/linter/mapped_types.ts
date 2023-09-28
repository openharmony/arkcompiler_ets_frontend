/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

type OptionsFlags<Type> = {
    [Property in keyof Type]: boolean;
};
type FeatureFlags = {
    darkMode: () => void;
    newUserProfile: () => void;
};
type FeatureOptions = OptionsFlags<FeatureFlags>;

// Removes 'readonly' attributes from a type's properties
type CreateMutable<Type> = {
    -readonly [Property in keyof Type]: Type[Property];
};
type LockedAccount = {
    readonly id: string;
    readonly name: string;
};
type UnlockedAccount = CreateMutable<LockedAccount>;

// Removes 'optional' attributes from a type's properties
type Concrete<Type> = {
    [Property in keyof Type]-?: Type[Property];
};
type MaybeUser = {
    id: string;
    name?: string;
    age?: number;
};
type User = Concrete<MaybeUser>;

// Creates new property names from prior ones:
type Getters<Type> = {
    [Property in keyof Type as `get${Capitalize<string & Property>}`]: () => Type[Property]
};
interface Person {
    name: string;
    age: number;
    location: string;
}
type LazyPerson = Getters<Person>;

// Combine with Conditional type:
type ExtractPII<Type> = {
    [Property in keyof Type]: Type[Property] extends { pii: true } ? true : false;
};
type DBFields = {
    id: { format: "incrementing" };
    name: { type: string; pii: true };
};
type ObjectsNeedingGDPRDeletion = ExtractPII<DBFields>;