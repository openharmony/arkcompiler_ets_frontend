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

declare class ClassWithSymbols {
    public readonly [x: number]: string;
    public /* @@ label1 */[x: number]: /* @@ label2 */(/* @@ label3 */) /* @@ label4 */=> /* @@ label5 */void;
}


/* @@@ label1 Error SyntaxError: Only one index signature can exist in a class  */
/* @@@ label2 Error SyntaxError: Return type of index signature from exported class or interface need to be identifier.  */
/* @@@ label3 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label4 Error SyntaxError: Unexpected token '=>'.  */
/* @@@ label5 Error SyntaxError: Unexpected token 'void'.  */
