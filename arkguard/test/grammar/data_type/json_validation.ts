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

let json_str = '[{"name":"小勇","age":18},{"name":"小刚","age":23},{"name":"大勇","age":25},{"name":"小花","age":13},{"name":"小黑","age":34},{"name":"小白","age":26}]';

let json_obj = JSON.parse(json_str);

let json_str2 = JSON.stringify(json_obj);

assert(json_str === json_str2, 'success');
