/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

type Flags<T> = {
  [P in keyof T]: boolean;
};
type MyFlags = {
  firstFlag: () => void;
  secondFlag: () => void;
};
type MyOptions = Flags<MyFlags>;

// Removes 'readonly' attributes from a type's properties
type RemoveReadonly<T> = {
  -readonly [P in keyof T]: T[P];
};
type MutableObject = {
  readonly id: string;
  readonly name: string;
};
type ImmutableObject = RemoveReadonly<MutableObject>;

// Removes 'optional' attributes from a type's properties
type RemoveOptional<T> = {
  [P in keyof T]-?: T[P];
};
type PartialObject = {
  id: string;
  name?: string;
  age?: number;
};
type CompleteObject = RemoveOptional<PartialObject>;

// Creates new property names from prior ones:
type PropertiesToGetters<T> = {
  [P in keyof T as `get${Capitalize<
    string & P
  >}`]: () => T[P];
};
interface User {
  login: string;
  email: string;
  data: string;
}
type LazyUser = PropertiesToGetters<User>;

// Combine with Conditional type:
type ExtractBar<T> = {
  [Prop in keyof T]: T[Prop] extends { bar: true }
    ? true
    : false;
};
type Entity = {
  identity: { name: 'Object' };
  details: { foo: string; bar: true };
};
type ExtractedProps = ExtractBar<Entity>;
