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

function main(): void {
  let length = 10;
  for (let i = 0; i < ( let f = ((x: A | null | undefined) => x as A); f(new A());
); i += 3) {
  }
}

/* @@? 18:19 Error TypeError: Bad operand type, the types of the operands must be numeric, same enumeration, or boolean type. */
/* @@? 18:25 Error SyntaxError: Unexpected token 'let'. */
/* @@? 18:25 Error SyntaxError: Unexpected token, expected ')'. */
/* @@? 18:29 Error SyntaxError: Expected ';', got 'identification literal'. */
/* @@? 18:29 Error TypeError: Unresolved reference f */
/* @@? 18:38 Error TypeError: Cannot find type 'A'. */
/* @@? 18:68 Error TypeError: Cannot find type 'A'. */
/* @@? 18:70 Error SyntaxError: Expected ')', got ';'. */
/* @@? 18:72 Error TypeError: This expression is not callable. */
/* @@? 18:78 Error TypeError: Cannot find type 'A'. */
/* @@? 19:1 Error SyntaxError: Unexpected token ')'. */
/* @@? 19:4 Error TypeError: Unresolved reference i */
/* @@? 19:10 Error SyntaxError: Unexpected token ')'. */
/* @@? 19:10 Error SyntaxError: Unexpected token ')'. */
/* @@? 19:10 Error SyntaxError: Unexpected token ')'. */
