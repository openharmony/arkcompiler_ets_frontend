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

class Klass {
    static {
        /* @@ label */this./* @@ label1 */a = 13;
    }

    static a: int = 12;
}

/* @@@ label Error TypeError: 'this' cannot be referenced from a static context  */
/* @@@ label1 Error TypeError: 'a' is a static property of 'Klass'  */
