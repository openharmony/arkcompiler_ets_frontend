/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import assert = require('assert');

let suits = ['hearts', 'spades', 'clubs', 'diamonds'];

function pickCard(x: { suit: string; card: number; }[]): number;
function pickCard(x: number): { suit: string; card: number; };
function pickCard(x): any {
  if (typeof x === 'object') {
    return Math.floor(0.5 * x.length);
  }
  // Otherwise just let them pick the card
  else if (typeof x === 'number') {
    let pickedSuit = Math.floor(x / 13);
    return {suit: suits[pickedSuit], card: x % 13};
  }
}

let myDeck = [{suit: 'diamonds', card: 2}, {suit: 'spades', card: 10}, {suit: 'hearts', card: 4}];
let pickedCard1 = myDeck[pickCard(myDeck)];

assert(pickedCard1.card === 10, 'success');
assert(pickedCard1.suit === 'spades', 'success');

let pickedCard2 = pickCard(15);


assert(pickedCard2.card === 2, 'success');
assert(pickedCard2.suit === 'spades', 'success');