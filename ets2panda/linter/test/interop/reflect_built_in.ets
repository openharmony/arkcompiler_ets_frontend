/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
import { X } from "./oh_modules/reflect_export"

export function foo(prx: Object) {
 Reflect.get(prx, 'a')  // 'hello'
 Reflect.set(prx, 'a', 'world')  // true
 Reflect.ownKeys(prx)  // ['a']
}

export function bar(obj: Object) {
    return Reflect.has(obj, 'prop');
}

foo(new X()); //illegal

bar(new X()); //illegal

import {Reflect1} from "./oh_modules/reflect_export"
import {obj_Reflect1} from "./oh_modules/reflect_export"
import {objInter} from "./oh_modules/reflect_export"

function reflect_method2(prx: Object) {
    Reflect.get(prx, 'a')  // 'hello'
    Reflect.set(prx, 'a', 'world')  // true
    Reflect.ownKeys(prx)  // ['a']
}

reflect_method2(new Reflect1());
Reflect.get(new Reflect1(), 'a')
Reflect.set(new Reflect1(), 'a', 'world')
Reflect.ownKeys(new Reflect1())
let obj = new Reflect1()
reflect_method2(obj);
Reflect.get(obj, 'a')
Reflect.set(obj, 'a', 'world')
Reflect.ownKeys(obj)

reflect_method2(obj_Reflect1);
Reflect.get(obj_Reflect1, 'a')
Reflect.set(obj_Reflect1, 'a', 'world')
Reflect.ownKeys(obj_Reflect1)

reflect_method2(objInter);
Reflect.get(objInter, 'a')
Reflect.set(objInter, 'a', 'world')
Reflect.ownKeys(objInter)

