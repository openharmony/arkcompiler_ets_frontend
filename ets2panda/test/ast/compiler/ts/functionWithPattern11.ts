/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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


function foo([a = 2, { b: [c = 6, d] = [true, [5n, "foo"]], t = { a: 3, b: { a: 2, b: 5n } } }], { r: [[r, z = 5] = [true]] = [[2, "foo"]] }) {

}

foo([2, { b: [true, []], t: { a: 1, /* @@ label */z: "foo" } }, 5n], {});

/* @@@ label Error TypeError: Object literal may only specify known properties, and "z" does not exist in type '{ a: number; b: { a: number; b: bigint; }; }'.  */
