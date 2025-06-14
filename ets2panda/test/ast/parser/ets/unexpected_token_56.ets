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

for await (/* @@ label1 */;/* @@ label2 */;/* @@ label3 */i < /* @@ label4 */count/* @@ label5 */; ++i/* @@ label6 */) {
    /* @@ label8 */result = result + /* @@ label9 */p[i]!.awaitResolution() * /* @@ label10 */a[i];
}
for (let i?: Number = 1;;)  { break; }

/* @@@ label1 Error SyntaxError: Unexpected token ';'. */
/* @@@ label2 Error SyntaxError: Unexpected token ';'. */
/* @@@ label3 Error TypeError: Unresolved reference i */
/* @@@ label3 Error TypeError: Bad operand type, the types of the operands must be numeric, same enumeration, or boolean type. */
/* @@@ label4 Error TypeError: Function name 'count' used in the wrong context */
/* @@@ label5 Error SyntaxError: Expected ')', got ';'. */
/* @@@ label6 Error SyntaxError: Unexpected token ')'. */
/* @@@ label6 Error SyntaxError: Unexpected token ')'. */
/* @@@ label6 Error SyntaxError: Unexpected token ')'. */
/* @@@ label8 Error TypeError: Unresolved reference result */
/* @@@ label9 Error TypeError: Unresolved reference p */
/* @@@ label9 Error TypeError: Indexed access is not supported for such expression type. */
/* @@@ label10 Error TypeError: Unresolved reference a */
/* @@@ label10 Error TypeError: Indexed access is not supported for such expression type. */
