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

import type {IControlFlowFatteningOption} from './IControlFlowFatteningOption';
import type {IDataObfuscationOption} from './IDataObfuscationOption';
import type {IBogusControlFlowOption} from './IBogusControlFlowOption';
import type {INameObfuscationOption} from './INameObfuscationOption';
import type {IInstructionObfuscationOption} from './IInstructionObfuscationOption';
import type {IHideOhApiOption} from './IHideOhApiOption';

export interface IOptions {
  // Whether to generate compact code
  readonly mCompact?: boolean;

  // Whether to remove comments;
  readonly mRemoveComments?: boolean;

  // Whether to disable console output
  readonly mDisableConsole?: boolean;

  // whether to disable hilog output
  readonly mDisableHilog?: boolean;

  // Whether to do code simplification, includes variable declarations merging, expression merging...
  readonly mSimplify?: boolean;

  // whether to hide openHarmony api
  readonly mHideOhApi?: IHideOhApiOption;

  // Whether to do Name Obfuscation
  readonly mNameObfuscation?: INameObfuscationOption;

  // Whether to insert bogus control flow.
  readonly mBogusControlFlow?: IBogusControlFlowOption;

  // Whether to do control flow flattening
  readonly mControlFlowFlattening?: IControlFlowFatteningOption;

  // Whether to do data obfuscation
  readonly mDataObfuscation?: IDataObfuscationOption;

  // Whether to do Instruction obfuscation, includes obfuscating binary expression, logical expression, call expression.
  readonly mInstructionObfuscation?: IInstructionObfuscationOption;

  mNarrowFunctionNames?: Array<string>;

  mOutputDir?: string;

  readonly mOhSdkPath?: string;

  readonly mTopLevel?: boolean;

  readonly mEnableSourceMap?: boolean;

  readonly mEnableNameCache?: boolean;

  readonly apiSavedDir?: string;

  readonly applyReservedNamePath?: string;
}
