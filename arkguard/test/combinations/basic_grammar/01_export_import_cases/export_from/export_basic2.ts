/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

type numAlias = number;

export let var2 = 2;

export function plus(para1: numAlias, para2: number) {
  return para1 + para2;
}

export class Person {
  prop1: numAlias;
  prop2: string;
  constructor(params) {
    this.prop1 = params;
  }
  doubleProp1(): numAlias {
    return 2 * this.prop1;
  }
}