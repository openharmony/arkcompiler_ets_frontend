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

class Test {
    public async native /* @@ label */bar(): Promise;
}

/* @@@ label Error SyntaxError: Native method cannot be async.  */
/* @@? 17:46 Error TypeError: Type 'Promise<T>' is generic but type argument were not provided. */
/* @@? 17:42 Error TypeError: Return type of async function must be 'Promise'. */
