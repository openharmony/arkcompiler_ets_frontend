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

export interface IControlFlowFatteningOption {
  /**
   * Whether to enable control flow obfuscation
   */
  readonly mEnable: boolean;

  /**
   * Probability of  control flow  obfuscation
   */
  readonly mThreshold: number;

  /**
   * skip obfuscation in loop for performance
   */
  readonly mSkipLoop?: boolean;

  /**
   * advance switch
   */
  readonly mAdvance?: boolean;

  /**
   *  Whether to flatten if statement
   */
  readonly mIfFlattening?: boolean;

  /**
   * Whether to flatten switch statement
   */
  readonly mSwitchFlatting?: boolean;

  /**
   * Whether to convert case constants to expression
   */
  readonly mCaseToExpression?: boolean;
}
