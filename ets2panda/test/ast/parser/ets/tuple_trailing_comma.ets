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


let a: [number, w: number, number,] = [1, 2, 3,];
let b: [number, /* @@ label */,number, number,] = [1, 2, 3,];

/* @@? 17:17 Error TypeError: Cannot find type 'w'. */
/* @@? 17:18 Error SyntaxError: Unexpected token, expected ',' or ']'. */
/* @@? 17:18 Error SyntaxError: Unexpected token ':'. */
/* @@? 17:20 Error SyntaxError: Unexpected token 'number'. */
/* @@? 17:20 Error TypeError: Type name 'number' used in the wrong context */
/* @@? 17:26 Error SyntaxError: Unexpected token ','. */
/* @@? 17:28 Error SyntaxError: Unexpected token 'number'. */
/* @@? 17:28 Error TypeError: Type name 'number' used in the wrong context */
/* @@? 17:34 Error SyntaxError: Unexpected token ','. */
/* @@? 17:35 Error SyntaxError: Unexpected token ']'. */
/* @@@ label Error SyntaxError: Invalid Type. */
