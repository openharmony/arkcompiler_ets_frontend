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

namespace ConflictedSpace {
    export let InnerSpace = 123;

    export namespace InnerSpace {
        export let value = 456;
    }
}

/* @@? 19:22 Error TypeError: Variable 'InnerSpace' has already been declared. */
/* @@? 19:22 Error TypeError: Merging declarations is not supported, please keep all definitions of classes, interfaces and enums compact in the codebase! */
