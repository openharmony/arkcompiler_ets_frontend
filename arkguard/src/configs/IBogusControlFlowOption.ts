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

/**
 * Generation type of the inserted block statement
 */
export enum BogusBlockType {
  /**
   * Use other available block and rename variables in block
   */
  OTHER_BLOCK_RENAME = 1,

  /**
   * Use a deformation of current block, replaces with some basic operations
   */
  CURRENT_BLOCK_DEFORM = 2,
}

export interface IBogusControlFlowOption {
  /**
   * Whether to enable bogus control flow obfuscation
   */
  readonly mEnable: boolean;

  /**
   * Probability of inserting bogus control flow into the target node
   */
  readonly mThreshold: number;

  /**
   * skip obfuscation in loop for performance
   */
  readonly mSkipLoop?: boolean;

  /**
   * Whether to use opaque predicates
   */
  readonly mUseOpaquePredicate: boolean;

  /**
   * Generation type of the inserted bogus block.
   */
  readonly mInsertBlockType: BogusBlockType;
}
