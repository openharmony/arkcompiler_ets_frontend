/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import assert = require('assert');

const NAME: string = 'SanYe';

assert(NAME === 'SanYe', 'success');

const F4: String[] = ['Jay', 'JJ', 'Gang', 'Bai'];

const [JAY, JJ, GANG, BAI] = F4;

assert(JJ === 'JJ', 'success');

const CHUAN = {
  name: 'zhou',
  age: 30,
  song: function (): string {
    return 'I can sing qinghua'
  }
};

let {name, age, song} = CHUAN;

assert(age === 30, 'success');
