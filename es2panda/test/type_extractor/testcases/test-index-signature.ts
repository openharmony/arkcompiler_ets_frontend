/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


interface I {
  [key: string]: number;
}

const interfaceObj: I = {
  a: 1,
  b: 2
};

let literalObj: {[key: string]: number} = {"a": 3, "b": 4};

class Rectangle {
    [id: number]: number;
    [property: string]: number;
}

class Square extends Rectangle {};

let logoA = new Rectangle();
logoA[0] = 1;
logoA["Width"] = 3;
logoA["Length"] = 5;

let logoB = new Square();
logoB[0] = 2;
logoB["Width"] = logoB["Length"] = 4;
