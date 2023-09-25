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


class Rectangle {                  // indexSignatureType-Rectangle 102 -> classType-Rectangle 101
    [id: number]: number;
    [property: string]: number;
}

class Square {                     // indexSignatureType-Square 104 -> classType-Square 103
    [id: number]: number;          // Only the non-static index signature is recorded now
    static [property: string]: number;
}

class Round {                      // classType-Round 105
    static [property: string]: number;
}

class ShapeA extends Rectangle {}; // classType-ShapeA 106 -> indexSignatureType-Rectangle 102
class ShapeB extends Square {};    // classType-ShapeB 107 -> indexSignatureType-Square 104
class ShapeC extends Round {};     // classType-ShapeC 108 -> classType-Round 105

let rec = new Rectangle();         // classInstanceType-rec 109 -> indexSignatureType-Rectangle 102
let sqr = new Square();            // classInstanceType-sqr 110 -> indexSignatureType-Square 104
let rnd = new Round();             // classInstanceType-rnd 111 -> classType-Round 105

let logoA = new ShapeA();          // classInstanceType-logoA 112 -> classType-ShapeA 106
let logoB = new ShapeB();          // classInstanceType-logoB 113 -> classType-ShapeB 107
let logoC = new ShapeC();          // classInstanceType-logoC 114 -> classType-ShapeC 108