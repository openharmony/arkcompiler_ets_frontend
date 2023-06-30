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
import {start} from "repl";

interface Counter {
  (start: number): string;

  interval: number;

  reset(): void;
}

function getCounter(): Counter {
  const counter = <Counter>function (start: number) { };
  counter.interval = 10;
  counter.reset = function ():void {
    counter.interval = 30
  };
  return counter;
}

let c = getCounter();
c(10);
c.reset();

assert(c.interval === 30, 'success')