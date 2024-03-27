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

function testFunc(mx: number[][]): void {  
  outerLoop: for (let i = 0; i < mx.length; i++) {  
    for (let j = 0; j < mx[i].length; j++) {  
      if (mx[i][j] === 5) {  
        break outerLoop; 
      }  
    }  
  }  
  return; 
}

function processArray(array: number[]): void {  
  outerLoop: for (let i = 0; i < array.length; i++) {  
    if (array[i] % 2 === 0) {  
      continue outerLoop; 
    }  
    console.log(array[i]);
  }  
}