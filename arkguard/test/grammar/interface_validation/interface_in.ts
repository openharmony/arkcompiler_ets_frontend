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

import assert from 'assert';

let cards = {
  poker: ["hearts", "spades", "clubs", "diamonds"],
  createCardPicker: function () {
    return () => {
      let pickedCard = 42;
      let pickedPoker = pickedCard / 14;

      return {type: this.poker[pickedPoker], card: pickedCard / 14};
    }
  }
}

let cardPicker = cards.createCardPicker();
let pickedCard = cardPicker();

assert(pickedCard.card === 3, 'success');

assert(pickedCard.type === 'diamonds', 'success');
