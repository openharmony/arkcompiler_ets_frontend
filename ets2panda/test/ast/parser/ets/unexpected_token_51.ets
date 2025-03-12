/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

function identity<Type>(arg: Type): Type {
  return arg;
}
let output = identity<string>
let output1 = identity<number>
console.log(/* @@ label */output(/* @@ label1 */"hehehe"))
console.log(/* @@ label2 */output(/* @@ label3 */4))

// bug with type error is here
/* @@@ label1 Error TypeError: Type '"hehehe"' is not compatible with type 'Type' at index 1  */
/* @@@ label Error TypeError: No matching call signature for invoke0("hehehe")  */
/* @@@ label3 Error TypeError: Type 'int' is not compatible with type 'Type' at index 1  */
/* @@@ label2 Error TypeError: No matching call signature for invoke0(int)  */

