/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { Autofix } from './autofixes/Autofixer';
import type { FaultID } from './Problems';

export interface ProblemInfo {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  start: number;
  end: number;
  type: string;
  severity: number;
  faultId: FaultID;
  problem: string;
  suggest: string;
  rule: string;
  ruleTag: number;
  autofixable?: boolean;
  autofix?: Autofix[];
  autofixTitle?: string;
}
