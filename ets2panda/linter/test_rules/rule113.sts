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


// fixable
enum Color {
    RED,
    GREEN
}
enum Color {
    YELLOW = 2
}
enum Color {
    BLACK = 3,
    BLUE
}
// ------

// not fixable
enum C {
    A = 1
}

const x = 6
let y = C.A

enum C{
    B = x
}
// ------

// not fixable
const d = 6

enum D {
    A = 1
}

enum D{
    B = d
}
// ------

// fixable
enum Str {
    A = 1,
    B = "abc"
}

enum Str{
    C = 2,
    D,
    E = "qwerty"
}
// ------

enum Empty {

}

enum Empty {

}
