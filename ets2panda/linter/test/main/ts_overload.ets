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

function makeDate(timestamp: number): Date;
function makeDate(m: number, d: number, y: number): Date;
function makeDate(mOrTimestamp: number, d?: number, y?: number): Date {
  if (d !== undefined && y !== undefined) {
    return new Date(y, mOrTimestamp, d);
  } else {
    return new Date(mOrTimestamp);
  }
}
const d1 = makeDate(12345678);
const d2 = makeDate(5, 5, 5);
const d3 = makeDate(1, 3);

class Vector {
  abstract foo(): void
  abstract foo(x: string): void
  abstract foo(x?: string): void {
    /body/
  }

  public fun(): void
  public fun(x: string): void
  public fun(x?: string): void {
    /body/
  }
}

abstract class absClass {
  abstract foo(): void
  abstract foo(x: string): void
  abstract foo(x?: string): void {
    /body/
  }

  constructor(x: number, y: number);

  constructor(magnitude: number);

  constructor(...args: number[]) {
      /* ... */
    }
}
function func(){
  console.log("ArkTs foo4")
}

func.val = "0xff";