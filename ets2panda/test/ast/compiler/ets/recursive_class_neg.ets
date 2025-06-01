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

class A<T extends A/* @@ label */<A<T>>>{}
class C extends A/* @@ label1 */<A/* @@ label2 */<C>>{}
/* A<C> does not satisfy the constraint due to invariance of T */

/* @@@ label Error TypeError: Type A<T> is not assignable to constraint type A<A<A<T>>>  */
/* @@@ label2 Error TypeError: Type C is not assignable to constraint type A<A<C>>  */
/* @@@ label1 Error TypeError: Type A<C> is not assignable to constraint type A<A<A<C>>>  */
