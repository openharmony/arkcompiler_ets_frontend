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

const a: Record<number, string> = {
    [((): number => 2)()]: '1'
}

const b: Record<number, (x: string) => number> = {
    [(():number => +("foo"))()]: function (y: string): number {
        return y.length;
    },
    [(():number => +("bar"))()]: (y: string):number => y.length
};

/* @@? 21:21 Error TypeError: Bad operand type, the type of the operand must be numeric type.  */
/* @@? 21:34 Error SyntaxError: Unexpected token.  */
/* @@? 21:34 Error SyntaxError: Unexpected token 'function'.  */
/* @@? 21:43 Error SyntaxError: Unexpected token.  */
/* @@? 21:44 Error SyntaxError: Unexpected token.  */
/* @@? 21:44 Error TypeError: Unresolved reference y  */
/* @@? 21:45 Error SyntaxError: Unexpected token.  */
/* @@? 21:47 Error TypeError: Type 'String' is not compatible with type 'Double' at index 1  */
/* @@? 21:47 Error TypeError: Type name 'string' used in the wrong context  */
/* @@? 21:53 Error SyntaxError: Unexpected token, expected ':'.  */
/* @@? 21:54 Error SyntaxError: Unexpected token ':'.  */
/* @@? 21:54 Error SyntaxError: Unexpected token.  */
/* @@? 21:56 Error TypeError: Type name 'number' used in the wrong context  */
/* @@? 21:63 Error SyntaxError: Unexpected token, expected ':'.  */
/* @@? 22:9 Error SyntaxError: Unexpected token.  */
/* @@? 22:9 Error SyntaxError: Unexpected token 'return'.  */
/* @@? 22:17 Error SyntaxError: Unexpected token, expected ':'.  */
/* @@? 22:18 Error TypeError: Unresolved reference length  */
/* @@? 22:24 Error SyntaxError: Unexpected token.  */
/* @@? 23:5 Error SyntaxError: Unexpected token '}'.  */
/* @@? 23:6 Error SyntaxError: Unexpected token ','.  */
/* @@? 23:6 Error SyntaxError: Unexpected token ','.  */
/* @@? 24:21 Error TypeError: Bad operand type, the type of the operand must be numeric type.  */
/* @@? 24:32 Error SyntaxError: Unexpected token ':'.  */
/* @@? 24:32 Error SyntaxError: Unexpected token ':'.  */
/* @@? 24:32 Error SyntaxError: Unexpected token ':'.  */
/* @@? 25:1 Error SyntaxError: Unexpected token '}'.  */
