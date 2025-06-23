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

type MyMap<K extends keyof RecordMap> = {
    kind: K
};

type RecordMap = { n: number };

let myMap: MyMap<"n"> = { kind: "n" };

/* Expected errors - these should NOT cause assertion failures or crashes: */
/* @@? 16:37 Error TypeError: The `keyof` keyword can only be used for class or interface type. */
/* @@? 16:41 Error SyntaxError: Invalid Type. */
/* @@? 17:11 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 17:11 Error TypeError: Unresolved reference K */
/* @@? 20:18 Error SyntaxError: Invalid Type. */
/* @@? 20:23 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 20:23 Error TypeError: Type name 'number' used in the wrong context */