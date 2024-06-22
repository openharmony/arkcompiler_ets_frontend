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

export function fooOriginal2() {
  return '11';
}

interface InterOriginal2 {
  interProp1: number;
}

class ClassOrinal2 {
  classProp1: number = 2;
}

export default function fooOrignal22() {
  return 22;
}

export {InterOriginal2, ClassOrinal2 as ClassAlis}