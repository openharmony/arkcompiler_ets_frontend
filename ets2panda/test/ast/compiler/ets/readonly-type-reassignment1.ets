/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

/*---
desc: Type Readonly<T> constructs a type with all properties of T set to readonly.
  It means that the properties of the constructed value cannot be reassigned. T must
  be a class or an interface type
name: readonly_type_reassignment_1
tags:
- compile-only
- negative
---*/

interface I {
  i: number;
  j: string;
}

function main() {
  let z: Readonly<I> = { i: 1.9, j: "some str"}
  /* @@ label */z.j = "new str"
}

/* @@@ label Error TypeError: The 'Readonly' property cannot be reassigned. */
