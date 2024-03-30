/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable low or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import collections from './@arkts.collections';

let array1: collections.Array<number> = new collections.Array<number>();
let set1: collections.Set<number> = new collections.Set<number>();

console.log(array1[0]); // Legal
const num = 123;
console.log(array1[num]); // Legal

console.log(array1["str"]); // Illegal
const str = "abc";
console.log(array1[str]); // Illegal

console.log(set1[0]); // Illegal
