/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

enum Color { Red, Green = 10, Blue }
enum Commands { Open = "fopen",  Close = "fclose" }

function foo(c: Color, d: Commands): Color {
    assertEQ(c, Color.Green)
    assertEQ(d, Commands.Close)
    return c;
}

function main() {
    let lambda = (c: Color, d: Commands) => { 
        assertEQ(c, Color.Green)
        assertEQ(d, Commands.Close)
        return d;
    };

    let green = Color.Green;
    let close = Commands.Close;
    assertEQ(foo(green, close), Color.Green)
    assertEQ(lambda(green, close), Commands.Close)
}
