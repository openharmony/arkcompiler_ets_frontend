/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");W
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export a /* @@ label */from /* @@ label1 */"./type"

/* @@? 13:8 Error SyntaxError: Cannot find name 'a' to export. */
/* @@? 13:24 Error SyntaxError: Unexpected token 'from'. */
/* @@? 13:24 Error TypeError: Unresolved reference from */
/* @@? 13:44 Error SyntaxError: Unexpected token './type'. */
