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

enum A {
    a = !3
}

enum B {
    a = 9(1)
}

enum C {
    a = 1,
    b = 100 > 1
}


/* @@? 17:9 Error TypeError: Enumeration members can be initialized only by compile-time expressions and initializers must be of the same type. */
/* @@? 21:9 Error TypeError: Enumeration members can be initialized only by compile-time expressions and initializers must be of the same type. */
/* @@? 26:9 Error TypeError: Enumeration members can be initialized only by compile-time expressions and initializers must be of the same type. */
