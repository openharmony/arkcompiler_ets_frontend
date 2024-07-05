/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import add from './namecacheTest7_export';
import { multiply, times } from './namecacheTest7_export';
import { PI, Student } from './namecacheTest7_export';
import { subtract, Lesson } from './namecacheTest7_export';
import type { customType } from './namecacheTest7_export';

let xiaoming = new Student("xiaoming", 12);
let xiaohong: Student = new Student("xiaohong", 11);
var value: customType = "hello";
const factor: number = 5;
let equal = (times(factor, PI) == multiply(factor, PI));
let math: Lesson = {
    id: 1,
    date: "2023"
};