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

interface Animal {
  live(): void;
}
interface Dog extends Animal {
  woof(): void;
}
type Example1 = Dog extends Animal ? number : string; // type Example1 = number
type Example2 = RegExp extends Animal ? number : string; // type Example2 = string

interface IdLabel {
  id: number /* some fields */;
}
interface NameLabel {
  name: string /* other fields */;
}
type NameOrId<T extends number | string> = T extends number
  ? IdLabel
  : NameLabel;
function createLabel<T extends number | string>(idOrName: T): NameOrId<T> {
  throw 1;
}
const a = createLabel('typescript'); // let a: NameLabel
const b = createLabel(2.8); // let b: IdLabel
const c = createLabel(Math.random() ? 'hello' : 42); // let c: NameLabel | IdLabel

type MessageOf<T> = T extends { message: unknown } ? T['message'] : never;
interface Email {
  message: string;
}
interface Dog {
  bark(): void;
}
type EmailMessageContents = MessageOf<Email>; // type EmailMessageContents = string
type DogMessageContents = MessageOf<Dog>; // type DogMessageContents = never

type Flatten<T> = T extends any[] ? T[number] : T;
type Str = Flatten<string[]>; // type Str = string
type Num = Flatten<number>; // type Num = number
