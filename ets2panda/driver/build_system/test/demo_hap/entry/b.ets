/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import {str, strd} from './c'
import {strA} from 'harA'
import {strB} from 'harB'
import {UIAbility, Lang, Hilog} from '@kit.AbilityKit'

function main() {
  let ui = new UIAbility();
  let lan = new Lang();
  let hilog = new Hilog();

  let hello_str = str;

  console.log(hello_str);
  console.log(strd);

  console.log(strA);
  console.log(strB);
}