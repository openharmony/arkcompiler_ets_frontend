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

import {randomBytes} from 'crypto';

import type {INameGenerator, NameGeneratorOptions} from './INameGenerator';

/**
 * @Desc: a name generator which used given length to generate random length-limiting name
 */
export class HexNameGenerator implements INameGenerator {
  private readonly mHexLength: number;
  private readonly mReservedNames: Set<string>;
  private readonly mWithPrefixSuffix: boolean;

  private readonly mHexPrefix: string;
  private readonly mHexSuffix: string;

  private mHistoryNameList: string[];

  /**
   * constructor for hex name generator
   * @param options: {hexLength: number}
   */
  constructor(options?: NameGeneratorOptions) {
    this.mHexLength = 4;
    if (options && options.hexLength) {
      this.mHexLength = options.hexLength;
    }

    this.mWithPrefixSuffix = options && options.hexWithPrefixSuffix;
    this.mReservedNames = options?.reservedNames;

    this.mHexPrefix = '_0x';
    this.mHexSuffix = '_';

    this.mHistoryNameList = [];
  }

  private generateName(): string {
    let buffer: Buffer = randomBytes(this.mHexLength);
    let generatedName: string = buffer.toString('hex');
    if (this.mWithPrefixSuffix) {
      return this.mHexPrefix + generatedName + this.mHexSuffix;
    }

    return generatedName;
  }

  /**
   * @return: null for end
   */
  public getName(): string {
    while (true) {
      let generatedName: string = this.generateName();
      if (!this.mHistoryNameList.includes(generatedName) && !this.mReservedNames?.has(generatedName)) {
        this.mHistoryNameList.push(generatedName);
        return generatedName;
      }
      const baseHex: number = 16;
      if (this.mHistoryNameList.length >= Math.pow(baseHex, this.mHexLength)) {
        return null;
      }
    }
  }

  public reset(): void {
    this.mHistoryNameList.length = 0;
  }
}
