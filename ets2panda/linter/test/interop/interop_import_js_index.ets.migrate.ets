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

let GeneratedImportVar_2 = ESValue.load('./interop_import_js_index_js');
let foo = GeneratedImportVar_2.getProperty('foo');
let GeneratedImportVar_1 = ESValue.load('./interop_import_js_rules_js');
let ff3 = GeneratedImportVar_1.getProperty('ff3');

let arr = foo.getProperty("arr")
arr.getProperty(1.0)
arr.setProperty(3.0, ESValue.wrap(4.0))

let arr1 = ff3.getProperty("arr")
let len: number = arr1.getProperty("length") as number
for (let i: number = 0.0; i < arr1.getProperty("length"); ++i) {
    console.log(arr1.getProperty(i).toNumber()+'');  //error
    let x = arr1.getProperty(i).toNumber()  //error
    arr1.setProperty(i, ESValue.wrap(0.0 //error
))  //error
    console.log(arr1.getProperty(i).toNumber()+'');  //error
}

for (let element of arr1) {  //error
  if (element == 8.0) {
    console.log("hi");
  }
}