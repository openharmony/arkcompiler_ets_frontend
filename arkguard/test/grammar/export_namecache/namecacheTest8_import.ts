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


import Student from './namecacheTest8_export';
import type { Particle, Lesson, Klass, customType } from './namecacheTest8_export';

function test(s: Student, p: Particle, l: Lesson, k: Klass, c: customType): void {
}

function init(p: Particle): void {
  p.row = 1;
  p.col = 2;
}

let students: Student[];
const math: Lesson = {
  id: 0,
  date: "2023",
  students: []
};