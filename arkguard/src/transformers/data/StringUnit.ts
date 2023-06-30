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

import type {Node, StringLiteralLike} from 'typescript';

export enum EncryptType {
  NONE = 0,
  BASE64 = 1,
  RC4 = 2,
  AES256 = 3,
}

export interface StringUnit {
  // content of a string unit
  'content': string,
  // order of string in array
  'order': number;
  // related node list of current string unit
  'nodeList': Node[];
  // encrypt algorithm for string
  'encryptAlgo': EncryptType;
  // content after encryption.
  'encryptContent': string;
}

export function createStringUnit(node: StringLiteralLike, index: number = -1): StringUnit {
  return {
    content: node.text,
    order: index,
    nodeList: [node],
    encryptAlgo: EncryptType.NONE,
    encryptContent: node.text,
  };
}
