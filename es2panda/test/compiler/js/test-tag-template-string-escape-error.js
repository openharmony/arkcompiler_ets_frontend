/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

function fn(str, substitute) {
    return substitute + str[1];
}
const str = 'ES2021';
const result = fn`${str} \ubuntu`;
const result1 = fn`${str} \123`;
const result2 = fn`${str} \0123`;
const result3 = fn`${str} \u{11ffff}`;
const result31 = fn`${str} \u{10ff}`;
const result4 = fn`${str} \u{12dd`;
const result41 = fn`${str} \u12dd`;
const result5 = fn`${str} \xgg`;
const result6 = fn`${str} \xaa`;

print(result);
print(result1);
print(result2);
print(result3);
print(result31);
print(result4);
print(result41);
print(result5);
print(result6);
