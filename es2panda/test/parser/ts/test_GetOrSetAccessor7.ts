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


interface Iest1 {
    get:number
}

interface Iest2 {
    get
}

interface Iest3 {
    get;
}

interface Iest4 {
    get?:number
}

interface Iest5 {
    get():number;
}

interface Iest6 {
    get<T>():number;
}

interface Iest7 {
    get?():number;
}

interface Iest8 {
    get,
}