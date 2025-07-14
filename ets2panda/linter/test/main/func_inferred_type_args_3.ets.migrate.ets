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
import {A} from './func_inferred_type_args_ts';
import B from './func_inferred_type_args_ts'
import A2 from './func_inferred_type_args_ts2'
import {A3} from './func_inferred_type_args_ts2'
import { HashMap } from '@kit.ArkTS';

function test() {
  const a = new A();
  a.map = new Map<string, B>(); //error
}
function test2() {
  const a = new A2();
  a.map = new Map(); //error
}
function test3() {
  const a = new A3();
  a.map = new Map<string, B>(); //error
}

class A4 {
  id?: string;
  map?: HashMap<string, Demo>;
}
class  Demo{}

function test4() {
  const a = new A4();
  a.map = new HashMap<string, Demo>(); //error
}