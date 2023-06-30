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

interface Square {
  kind: 'square';
  size: number;
}

interface Rectangle {
  kind: 'rectangle';
  width: number;
  height: number;
}

interface Circle {
  kind: 'circle';
  radius: number;
}

type Shape = Square | Rectangle | Circle;

function area(s: Shape): number {
  let result: number;
  switch (s.kind) {
    case 'square':
      result = s.size * s.size;
      break;
    case 'rectangle':
      result = s.height * s.width;
      break;
    case 'circle':
      result = Math.PI * s.radius * s.radius;
      break;
  }
  return result;
}

let a = {kind: 'square', size: 3};

const targetArea: number = 9;
assert(area(<Square>a) === targetArea, 'success');