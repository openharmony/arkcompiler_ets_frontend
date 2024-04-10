/*
 Copyright (c) 2024 Huawei Device Co., Ltd.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 *
 http://www.apache.org/licenses/LICENSE-2.0
 *
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.limitations under the License.
 */

function loop1(a) {
  let v = undefined;
  while (true) {
    v = a;
    a = 0.0;
  }
}

function loop2() {
  let v = "1";
  let unused1 = undefined;
  let unused2 = undefined;
  let unused3 = undefined;
  let c = 0;
  
  do {
    unused1 = v;
    unused2 = v;
    unused3 = v;
    v = 1;
    c++;
  } while ((() => {
    const ret = c < 5;
    return ret;
  })());

  print(c);
}

loop2(5);
print("compile success");
