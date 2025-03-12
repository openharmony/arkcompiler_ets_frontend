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

function foo(index:number){
  let an_array = [1,2,3]
  let a = an_array[index]
  let a1 = an_array[index + 1]
  let a2 = an_array[index + 1.1]
  let b = an_array[1.23]
  let c = an_array[true]
  let d = an_array['index']
  let e = an_array[undefined]
  let f = an_array[null]
  let g = an_array[]
  let h = an_array[12.]
  let i = an_array[12.0]
  let j = an_array[0]
}