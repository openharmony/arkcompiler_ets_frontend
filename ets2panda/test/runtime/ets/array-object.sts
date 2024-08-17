/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

function main(): void {
  let arr1: Int[] = [1,2,3,4,5];
  let arr2: int[] = [1,2,3,4,5];
  let object_array: Object[] = arr1 as Object[];
  let object: Object = arr1 as Object;

// TypeError: Cannot access property of non-object or non-enum type
// arr1.toString();
// arr2.toString();
// object_array.toString();

  object.toString();

//  TypeError: Cannot access property of non-object or non-enum type
//  arr1.$_hashCode();
//  arr2.$_hashCode();
//  object_array.$_hashCode();

  object.$_hashCode();

  assert(arr1 == arr1);
  assert(arr1 == object_array);
  assert(arr1 == object);
  assert(arr1 != arr2);

// Cannot cast type 'int[]' to 'Object[]'
//  let object_array2: Object[] = arr2 as Object[];
//  assert(object.equals(arr2 as Object) == false);

  assert(arr2 == arr2);
  assert(arr2 != new int[5]);
}
