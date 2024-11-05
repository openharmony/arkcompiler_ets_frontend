/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

/foo/bar ;

/foo/gx ;

/foo
/g ;

yield

funct\u{0069}on

`string ${expr

/* @@? 16:7 Error SyntaxError: Invalid RegExp flag  */
/* @@? 16:7 Error SyntaxError: Unexpected token 'identification literal'.  */
/* @@? 18:8 Error SyntaxError: Invalid RegExp flag  */
/* @@? 20:5 Error SyntaxError: Unterminated RegExp  */
/* @@? 20:5 Error SyntaxError: Expected an identifier  */
/* @@? 20:5 Error SyntaxError: Unexpected token 'identification literal'.  */
/* @@? 22:1 Error SyntaxError: Unexpected strict mode reserved keyword  */
/* @@? 24:1 Error SyntaxError: Escape sequences are not allowed in keywords  */
/* @@? 40:67 Error SyntaxError: Unexpected token, expected: '}'.  */
/* @@? 40:67 Error SyntaxError: Unterminated string  */
/* @@? 40:67 Error SyntaxError: Unexpected token, expected '${' or '`'  */
/* @@? 40:67 Error SyntaxError: Unexpected token, expected '`'  */
