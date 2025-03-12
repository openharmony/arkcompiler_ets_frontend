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

interface Base { n: number }
interface Child extends Base { a: string }

const b1: Base = { n: 200 }
const b2: Base = /* @@ label */{ ...{n: 200} }
const c1: Child = /* @@ label1 */{ ...b1, a: "a" }

/* @@@ label Error TypeError: The object literal properties must be key-value pairs */
/* @@@ label1 Error TypeError: The object literal properties must be key-value pairs */