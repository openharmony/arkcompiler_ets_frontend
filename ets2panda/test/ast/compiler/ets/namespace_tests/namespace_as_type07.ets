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
namespace MySpace {
    let a:string = "1"
}

class A{
    a:MySpace
}

let tuple:[int, string, MySpace] = [1, "1", new MySpace()]
let union:int|string|MySpace = 1

/* @@? 23:25 Error TypeError: Namespace 'MySpace' cannot be used as a type.  */
/* @@? 24:22 Error TypeError: Namespace 'MySpace' cannot be used as a type.  */
/* @@? 23:49 Error TypeError: Namespace 'MySpace' cannot be used as a type.  */
/* @@? 20:7 Error TypeError: Namespace 'MySpace' cannot be used as a type.  */