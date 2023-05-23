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
import {OrderedNameGenerator} from './OrderedNameGenerator';
import {DisorderNameGenerator} from './DisorderNameGenerator';
import {HexNameGenerator} from './HexNameGenerator';
import {DictionaryNameGenerator} from './DictionaryNameGenerator';
import {ReservedNameGenerator} from './ReservedNameGenerator';
import {UnderlineNameGenerator} from './UnderlineNameGenerator';

export enum NameGeneratorType {
  ORDERED = 1,
  DISORDERED = 2,
  HEX = 3,
  DICTIONARY = 4,
  RESERVED_NAME = 5,
  UNDERLINE = 6,
}

export function getNameGenerator(generatorType: NameGeneratorType, options?: NameGeneratorOptions): INameGenerator {
  // 10 branch is max in switch
  switch (generatorType) {
    case NameGeneratorType.ORDERED:
      return new OrderedNameGenerator(options);
    case NameGeneratorType.DISORDERED:
      return new DisorderNameGenerator(options);
    case NameGeneratorType.HEX:
      return new HexNameGenerator(options);
    case NameGeneratorType.DICTIONARY:
      return new DictionaryNameGenerator(options);
    case NameGeneratorType.RESERVED_NAME:
      return new ReservedNameGenerator(options);
    case NameGeneratorType.UNDERLINE:
      return new UnderlineNameGenerator(options);
    default:
      console.error('name generator type in getGenerator() is not support');
      return new OrderedNameGenerator(options);
  }
}
