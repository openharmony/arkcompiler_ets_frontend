/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

let a = [1, 2, 3]
a[0] = /* @@ label */"1"

/* @@? 17:1 Error TypeError: No matching indexing signature for $_set(int, "1") */
/* @@? 17:3 Error TypeError: Type 'int' is not compatible with type 'double' at index 1 */
/* @@? 17:3 Error TypeError: Cannot find index access method with the required signature. */
/* @@? 17:22 Error TypeError: Type '"1"' is not compatible with type 'Double' at index 2 */
