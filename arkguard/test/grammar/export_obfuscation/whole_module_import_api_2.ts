/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as moduleTemp from './whole_module_export_api_2';

moduleTemp.func11(3,4)
let classdemo11Obj = new moduleTemp.classDemo11(1);
let classdemo12Obj = new moduleTemp.classDemo12(2);
const tmpValue1 = moduleTemp.valueTemp11;
