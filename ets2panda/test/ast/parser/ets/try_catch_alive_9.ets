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

function foo(): int {
    try {
        return 0;
    } catch (e) {
        return 0;
        /* @@ label */let a = 2; // unreachable statement
    } finally /* @@ label1 */{
        return 0;
    }
}

/* @@@ label Warning Warning: Unreachable statement.  */
/* @@@ label1 Warning Warning: Finally clause cannot complete normally  */
