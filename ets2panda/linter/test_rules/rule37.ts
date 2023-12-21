/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

let regex: RegExp = /bc*d/

let regex2: RegExp = new RegExp("/bc*d/")

const regex3 = /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
const regex4: RegExp = new RegExp('^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$');

class A {
    static readonly classregex0: RegExp = /bc*d/

    static readonly classregex2 = /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;

    classregex3: RegExp = new RegExp("bc*d");

    static staticMethodOne() {
        let regex = /bc*d/
    }

    static staticMethodTwo() {
        let regex: RegExp = new RegExp("/bc*d/");
    }

    methodOne() {
        let regex = /bc*d/
    }

    methodTwo() {
        let regex: RegExp = new RegExp("/bc*d/");
    }

    methodRet(): RegExp {
        return /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
    }
}

const regexLambda = () => /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
