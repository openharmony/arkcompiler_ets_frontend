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

/**
 * @Desc: a name generator which use given identifiers to get incremental obfuscated name
 */
export class DictionaryNameGenerator implements INameGenerator {
  private readonly mDictionaryList: string[];
  private readonly mReservedNames: Set<string>;

  private mDictIndex: number;
  private mTransformNumber: number;

  /**
   *
   * @param options: {dictionaryList: list}
   */
  constructor(options?: NameGeneratorOptions) {
    this.mDictionaryList = (options && options.dictionaryList) ? options.dictionaryList : ['hello', 'world', 'dictionary', 'light', 'thunder', 'storm'];
    this.mReservedNames = options?.reservedNames;

    this.mDictIndex = 0;
    this.mTransformNumber = 0;
  }

  /**
   * @return: null for end
   */
  public getName(): string {
    if (this.mDictIndex >= this.mDictionaryList.length) {
      return null;
    }

    let originIdentifier: string[] = Array.from(this.mDictionaryList[this.mDictIndex].toLowerCase());
    const BINARY_RADIX: number = 2;
    let binary: string = this.mTransformNumber.toString(BINARY_RADIX).split('').reverse().join('');
    let countTrue: number = 0;
    for (let i = 0; i < binary.length; i++) {
      if (binary[i] === '1') {
        originIdentifier[i] = originIdentifier[i].toUpperCase();
        countTrue += 1;
      }
    }

    this.mTransformNumber += 1;
    if (countTrue >= originIdentifier.length) {
      this.mDictIndex += 1;
      this.mTransformNumber = 0;
    }

    if (this.mReservedNames?.has(originIdentifier.join(''))) {
      return this.getName();
    }

    return originIdentifier.join('');
  }

  public reset(): void {
    this.mDictIndex = 0;
    this.mTransformNumber = 0;
  }
}
