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
  function main(){
   let a = 1;
   a/* @@ label */~/* @@ label1 */!/* @@ label2 */;
  }
/* @@@ label Error SyntaxError: Unexpected token '~'. */
/* @@@ label1 Error TypeError: Bad operand type, the type of the operand must be numeric type. */
/* @@@ label2 Error SyntaxError: Unexpected token ';'. */
