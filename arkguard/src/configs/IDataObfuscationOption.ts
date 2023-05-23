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

import type {EncryptType} from '../transformers/data/StringUnit';

export interface IBooleanOption {
  readonly mEnable: boolean;

  readonly mThreshold: number;

  /**
   * skip obfuscation in loop for performance
   */
  readonly mSkipLoop: boolean;
}

export interface INumberOption {
  readonly mEnable: boolean;

  readonly mThreshold: number;

  /**
   * skip obfuscation in loop for performance
   */
  readonly mSkipLoop: boolean;
}

export interface IStringOption {

  readonly mEnable: boolean;

  readonly mThreshold: number;

  /**
   * skip obfuscation in loop for performance
   */
  readonly mSkipLoop: boolean;

  readonly mSkipProperty: boolean;

  readonly mSplitString: boolean;

  readonly mStringArray: boolean;

  readonly mStringArrayThreshold: number;

  readonly mEncryptType: EncryptType;

  readonly mStringArrayShuffle: boolean;

  readonly mStringArrayCallsTransform: boolean;

  readonly mStringArrayCallsThreshold: number;

  mReservedStrings: string[];

  readonly mObfuscationString: string[];
}

export interface IDataObfuscationOption {

  readonly mEnable: boolean;

  readonly mNumberOption: INumberOption;

  readonly mStringOption: IStringOption;

  readonly mBooleanOption: IBooleanOption;
}
