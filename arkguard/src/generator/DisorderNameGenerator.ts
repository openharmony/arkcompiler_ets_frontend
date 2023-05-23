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

import type {INameGenerator, NameGeneratorOptions} from './INameGenerator';
import {ListUtil} from '../utils/ListUtil';

/**
 * @Desc: simple disordered name generator
 * e.g.: c, b, z, a, ..., d1, a1, z1, ...
 */
export class DisorderNameGenerator implements INameGenerator {
  private mCharIndex: number;
  private mLoopNumber: number;
  private mReservedNames: Set<string>;

  private readonly CHAR_COUNT: number = 26;
  private readonly CHAR_CODE_A: number = 97;

  private readonly mCharIndexList: number[];

  constructor(options?: NameGeneratorOptions) {
    this.mCharIndex = 0;
    this.mLoopNumber = 0;
    this.mReservedNames = options?.reservedNames;

    this.mCharIndexList = ListUtil.getInitList(this.CHAR_COUNT);
    ListUtil.shuffle(this.mCharIndexList);
  }

  private updateElements(): void {
    this.mCharIndex = (this.mCharIndex + 1) % this.CHAR_COUNT;

    if (this.mCharIndex === 0) {
      this.mLoopNumber += 1;
      ListUtil.shuffle(this.mCharIndexList);
    }
  }

  public getName(): string {
    let generatedName: string = String.fromCharCode(this.CHAR_CODE_A + this.mCharIndexList[this.mCharIndex]);
    if (this.mLoopNumber > 0) {
      generatedName += this.mLoopNumber;
    }

    // update elements after generate name
    this.updateElements();
    if (this.mReservedNames?.has(generatedName)) {
      return this.getName();
    }

    return generatedName;
  }

  public reset(): void {
    this.mCharIndex = 0;
    this.mLoopNumber = 0;
    ListUtil.shuffle(this.mCharIndexList);
  }
}
