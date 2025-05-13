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
 
function main(){
	await test();
	
}

async function test() {
  let p = Promise.resolve(6);
  assertEQ(await p, 6);
  assertEQ(await p * 2, 12);
  assertEQ(await p / 2, 3);
  assertEQ(await p % 3, 0);
  assertEQ(await p + 1, 7);
  assertEQ(await p - 2, 4);
  assertEQ(await p === 6, true);
  assertEQ(await p != 4, true);
  assertEQ(1 << await p, 64);
  assertEQ(await p > 3, true);
  assertEQ(await p < 3, false);
  assertEQ(await p == 6, true);
  assertEQ(await p != 1, true);
  assertEQ(await p & 3, 2);
  assertEQ(await p ^ 2, 4);
  assertEQ(await p | 1, 7);

  let b = Promise.resolve(false);
  assertEQ(await b || true, true);
  let n = Promise.resolve(null);
  assertEQ(await n ?? 42, 42);
  let r = await p > 3 ? "yes" : "no";
  assertEQ(r, "yes");
  let x = await p;
  assertEQ(x, 6);
}