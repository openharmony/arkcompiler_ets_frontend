/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { foo, f1, f2, A, a1, a2 } from "./export_type_several_times_2.ets"

f1()
f2()
let c1: a1 = new a1()
let c2: a2 = new a2()

/* @@? 16:10 Error TypeError: Cannot find imported element 'foo' */
/* @@? 16:23 Error TypeError: Cannot find imported element 'A' */
