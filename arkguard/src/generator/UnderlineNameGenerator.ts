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
 * @Desc: a name generator which use underline to get obfuscated name
 */
export class UnderlineNameGenerator implements INameGenerator {
  private readonly mMaxLength: number;
  private readonly mReservedNames: Set<string>;

  private mCurrentLength: number;
  
  constructor(options: NameGeneratorOptions) {
    const maxValue: number = 128;
    this.mMaxLength = (options && options.underlineMaxLength) ? options.underlineMaxLength : maxValue;
    this.mReservedNames = options?.reservedNames;
    this.mCurrentLength = 1;
  }

  /**
   * @return: null for end
   */
  public getName(): string {
    if (this.mCurrentLength > this.mMaxLength) {
      return null;
    }

    let targetStr: string = '_'.repeat(this.mCurrentLength);
    this.mCurrentLength += 1;

    if (this.mReservedNames?.has(targetStr)) {
      return this.getName();
    }

    return targetStr;
  }

  public reset(): void {
    this.mCurrentLength = 1;
  }
}
