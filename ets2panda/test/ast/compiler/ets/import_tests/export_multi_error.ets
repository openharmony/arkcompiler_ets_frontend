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

export { /* @@ label */foo };

function bar(): int {
    return 1;
}

/*-----------------*/
function foo2(): void {}
class TestClass {}

export {foo2}
export type {TestClass as /* @@ label1 */foo2}

/*-----------------*/
export default function foo3(): void {}

export {
  foo3 as /* @@ label2 */bar
}

/*-----------------*/
export class A {}

export type {A as /* @@ label3 */AA};

/*-----------------*/
interface I {}

export type {I}
export type MyI = I
export type {/* @@ label4 */MyI}
/*-----------------*/

function f(){
    return 1;
}

export type {/* @@ label5 */f}
/*-----------------*/

export default /* @@ label6 */function TestFunc(): void {}
export default /* @@ label7 */function TestFuncToo(): void {}

/*-----------------*/
/* @@@ label6 Error TypeError: Only one default export is allowed in a module  */
/* @@@ label7 Error TypeError: Only one default export is allowed in a module  */
/* @@@ label3 Error SyntaxError: Name 'A' cannot be exported and type exported at the same time.  */
/* @@@ label4 Error SyntaxError: Cannot export the same 'MyI' type twice.  */
/* @@@ label5 Error SyntaxError: Can only type export class or interface.  */
/* @@@ label1 Error SyntaxError: The given name 'foo2' is already used in another export.  */
/* @@@ label1 Error SyntaxError: The given name 'foo2' is already used in another export.  */
/* @@@ label2 Error SyntaxError: Cannot export 'foo3', it was already exported.  */
/* @@@ label Error SyntaxError: Cannot find name 'foo' to export.  */
