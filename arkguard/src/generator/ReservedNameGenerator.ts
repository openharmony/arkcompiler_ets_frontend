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
 * need reserved keyword which contain transformDict character
 */
const gReservedIdentifier = [
  'let', 'return', 'break', 'continue', 'const', 'var', 'console', 'enum',
  'boolean', 'number', 'string', 'any', 'void', 'undefined', 'null',
  'never', 'function', 'declare', 'as', 'while', 'for', 'if', 'else',
  'true', 'false', 'try', 'catch', 'throw', 'type', 'class', 'new',
  'interface', 'export', 'readonly', 'private', 'public', 'extends',
  'implements', 'constructor', 'this', 'static', 'protected', 'switch',
  'case', 'default', 'typeof', 'instanceof', 'in', 'of', 'import', 'require',
  'module', 'from', 'abstract', 'async', 'namespace', 'arguments', '__global'
];

const gTransformDict = {
  'a': 'α',
  'b': 'þ',
  'c': 'ç',
  'e': 'è',
  'i': 'ì',
  'k': 'κ',
  'l': 'ι',
  'n': 'η',
  'o': 'ο',
  'p': 'ρ',
  'u': 'υ',
  'v': 'ν',
  'w': 'ω',
  'x': 'χ',
  'y': 'γ',
  'z': 'ζ'
};

/**
 * @Desc: a name generator which use reserved keywords similar words to get obfuscated name
 */
export class ReservedNameGenerator implements INameGenerator {
  private readonly mReservedNames: Set<string>;
  private readonly mTransformSet: Set<string>;

  private mIdIndex: number;
  private readonly mWordInfo: number[];
  private mWordIndex: number;

  constructor(options?: NameGeneratorOptions) {
    this.mTransformSet = new Set<string>();

    this.mReservedNames = options?.reservedNames;

    const dictKeys: string[] = Object.keys(gTransformDict);
    for (const key of dictKeys) {
      this.mTransformSet.add(key);
    }

    this.mIdIndex = 0;
    this.mWordIndex = 1;
    this.mWordInfo = [];

    this.getWordInfo(gReservedIdentifier[this.mIdIndex]);
  }

  private getWordInfo(originName: string): void {
    for (let i = 0; i < originName.length; i++) {
      if (this.mTransformSet.has(originName[i])) {
        this.mWordInfo.push(i);
      }
    }
  }

  private transformName(originName: string): string {
    let charArr: string[] = originName.split('');
    const BINARY_RADIX: number = 2;
    let binaryArr: string = this.mWordIndex.toString(BINARY_RADIX).split('').reverse().join('');
    for (let i = 0; i < binaryArr.length; i++) {
      if (binaryArr[i] === '1') {
        charArr[this.mWordInfo[i]] = gTransformDict[charArr[this.mWordInfo[i]]];
      }
    }

    this.mWordIndex += 1;
    if (this.mWordIndex === Math.pow(BINARY_RADIX, this.mWordInfo.length)) {
      this.mIdIndex += 1;
      this.mWordInfo.length = 0;
      this.mWordIndex = 1;

      if (this.mIdIndex < gReservedIdentifier.length) {
        this.getWordInfo(gReservedIdentifier[this.mIdIndex]);
      }
    }

    return charArr.join('');
  }

  /**
   * @return: null for end
   */
  public getName(): string {
    let originName: string = gReservedIdentifier[this.mIdIndex];

    let transformedName: string = this.transformName(originName);
    if (this.mIdIndex >= gReservedIdentifier.length) {
      return null;
    }

    if (this.mReservedNames?.has(transformedName)) {
      return this.getName();
    }

    return transformedName;
  }

  public reset(): void {
    this.mIdIndex = 0;
    this.mWordIndex = 1;
    this.mWordInfo.length = 0;
    this.getWordInfo(gReservedIdentifier[this.mIdIndex]);
  }
}
