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

class Grid {
  static origin = {x: 3, y: 4};

  calculateDistanceFromOrigin(point: { x: number; y: number; }): number {
    let xDist = (point.x - Grid.origin.x);
    let yDist = (point.y - Grid.origin.y);
    return (xDist * xDist + yDist * yDist) / this.scale;
  }

  constructor(public scale: number) {
  }
}

const grid1 = new Grid(1.0);  // 1x scale
const grid2 = new Grid(5.0);  // 5x scale

assert(grid1.calculateDistanceFromOrigin({x: 10, y: 10}) === 85, 'success');
assert(grid2.calculateDistanceFromOrigin({x: 10, y: 10}) === 17, 'success');