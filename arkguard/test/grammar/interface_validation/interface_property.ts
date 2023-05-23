/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import assert = require('assert');

function printLabel(labelledObj: { label: string }) {
  return labelledObj.label;
}

let myObj = {size: 10, label: 'Size 10 Object'};

assert(printLabel(myObj) === 'Size 10 Object', 'success');

interface LabelledValue {
  label: string;
}

function getLabel(labelledObj: LabelledValue) {
  return labelledObj.label;
}

let myObj1 = {size: 10, label: 'Size 10 Object'};

assert(getLabel(myObj1) === 'Size 10 Object', 'success');