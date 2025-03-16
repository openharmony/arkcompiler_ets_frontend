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

//import ets.util.List;
//import ets.lang.annotation.*;
class named_types  {
    text : ets.lang.String ;
    public static /* @@ label */class inner<T> {
        public /*@@ label1 */class innertoo  {
        }

    }

}

class auxilliary  {
    public  foo(): named_types.inner {
    }
}

/* @@@ label Error SyntaxError: Unexpected token. A constructor, method, accessor, or property was expected.  */
/* @@@ label1 Error SyntaxError: Unexpected token. A constructor, method, accessor, or property was expected. */
/* @@? 19:12 Error TypeError: Cannot find type 'ets'. */
/* @@? 19:16 Error TypeError: 'lang' type does not exist. */
/* @@? 19:21 Error TypeError: 'String' type does not exist. */
/* @@? 29:20 Error TypeError: Type 'inner<T>' is generic but type argument were not provided. */
