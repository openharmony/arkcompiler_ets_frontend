/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


var empty = Object.create(null);
var C, value;

for (C = class { get ['x' in empty]() { return 'via get'; } }; ; ) {
  value = C.prototype.false;
  break;
}

for (C = class { set ['x' in empty](param) { value = param; } }; ; ) {
  C.prototype.false = 'via set';
  break;
}
