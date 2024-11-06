/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

/**
 * hello world1
 */
console.log("--------")
const str1 = `这是第一行
这是第二行
这是第三行`;
console.log("----log 1----")
class ClassTest {
    prop1: string = '1'; // keep
    prop2: number = 2; // keep
    myprop: number = 3; // keep
    aaaaaaaa: number = 4; // keep
    h: number = 5;
    // keep functionkeep
    functionkeep() {
        console.log("---log 2-----")
        return `function name should be kept.`;
    }
 }
 console.log("---log 3-----")
 const str2 = `这是第四行
 这是第五行
 这是第六行`;
 
 /**
  * hello world2
  */
 function foo() {
     let var1 = 1;
     let var2= 2
 }