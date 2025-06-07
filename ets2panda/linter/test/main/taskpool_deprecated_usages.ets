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
'use static'

let baseInstance1: BaseClass = new BaseClass();
let array1 = new Array<BaseClass>();
array1.push(baseInstance1);
let task1 = new taskpool.Task(testFunc, array1, 10);
task1.setCloneList(array1);
task1.setTransferList(array1);
