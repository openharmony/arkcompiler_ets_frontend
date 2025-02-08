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

enum Color { Red, Green, Blue = 0}
assertTrue(Color.Red ? false : true)
assertTrue(Color.Green ? true : false)
assertTrue(!Color.Green ? false : true)
assertTrue(Color.Blue ? false : true)

while (Color.Red) { assertTrue(false)}
while (Color.Green) { break; }
while (Color.Blue) { assertTrue(false)}

let i = 0;
do {i++; if (i==2) break; } while (Color.Red); assertEQ(i, 1)
i = 0;
do {i++; if (i==2) break; } while (Color.Green); assertEQ(i, 2)
i = 0;
do {i++; if (i==2) break; } while (Color.Blue); assertEQ(i, 1)

let stop = false;
for (let i = 0; Color.Red; ++i) { stop = true; break; } assertEQ(stop, false)
stop = false;
for (let i = 0; Color.Green; ++i) { stop = true; break; } assertEQ(stop, true)
stop = false;
for (let i = 0; Color.Blue; ++i) { stop = true; break; } assertEQ(stop, false)

if (Color.Red) assertTrue(false)
if (Color.Green) assertTrue(true)
if (Color.Blue) assertTrue(false)

