/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

export default class ArrayUtils {

  /*
   * When performing a 'forEach' operation on an array,
   * elements that meet the conditions are allowed to be executed at the end.
   */
  static forEachWithDefer<T>(
    list: readonly T[],
    deferChecker: (value: T, index: number, array: readonly T[]) => boolean,
    callbackfn: (value: T, index: number, array: readonly T[]) => void,
    thisArg?: Object
  ): void {
    if (!list.length) {
      return;
    }

    const temp: number[] = [];
    list.forEach((item, index, array) => {
      if (deferChecker(item, index, array)) {
        temp.push(index);
        return;
      }
      callbackfn.call(thisArg, item, index, array);
    });

    temp.forEach((index) => {
      callbackfn.call(thisArg, list[index], index, list);
    });
  }
}
