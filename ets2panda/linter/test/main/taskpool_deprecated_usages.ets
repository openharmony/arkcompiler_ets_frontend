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
import ArrayBuffer,{ taskpool,ArrayList } from '@kit.ArkTS'
import { taskpool as tp } from '@kit.ArkTS'
import * as arkts from '@kit.ArkTS';
import { task as task7,Task } from './taskpool_deprecated_usages3';

let baseInstance1: BaseClass = new BaseClass();
let array = new Array<BaseClass>();
array.push(baseInstance1);
let task = new taskpool.Task(testFunc, array, 10);
task.setCloneList(array); //error
task.setTransferList(array); //error

function testFunc(){}
function test1():void {}

const array1: number[] =[1]
const transfer: ArrayBuffer[] =[]
let task1 = new taskpool.Task(testFunc, array1, 10);
task1.setCloneList(array1); //error
task1.setTransferList(transfer); //error

let task2 = new tp.Task(test1)
task2.setCloneList([])  //error
task2.setCloneList(transfer)  //error

let test3 = new tp.Task(test1)
test3.setCloneList([])  //error
test3.setCloneList([transfer])  //error

let task4 = new tp.Task(test1)
task4.setTransferList()  //error
task4.setTransferList([])  //error
task4.setTransferList(transfer)  //error

let test5 = new tp.Task(test1)
test5.setTransferList()  //error
test5.setTransferList([])  //error
test5.setTransferList(transfer)  //error

let task6 = new arkts.taskpool.Task(test1);
task6.setCloneList([]) //error
task6.setCloneList([transfer]) //error

task7.setCloneList(array1) //error
task7.setTransferList(transfer) //error
new task7.setTransferList(transfer) //error
new task7.setCloneList(array1) //error
new Task(test1).setTransferList(transfer)
new Task(test1).setCloneList(array1)
const task8 = new Task(testFunc);
task8.setCloneList(array1)