/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import type { ProblemInfo } from '../lib/ProblemInfo';
import { ProblemSeverity } from '../lib/ProblemSeverity';
import { TestMode } from './TestMode';
import type { TestProblemInfo } from './TestResult';

export function transformProblemInfos(fileProblems: ProblemInfo[], mode: TestMode): TestProblemInfo[] {
  return fileProblems.map<TestProblemInfo>((x) => {
    return {
      line: x.line,
      column: x.column,
      endLine: x.endLine,
      endColumn: x.endColumn,
      problem: x.problem,
      autofix: mode === TestMode.AUTOFIX ? x.autofix : undefined,
      suggest: x.suggest,
      rule: x.rule,
      severity: ProblemSeverity[x.severity]
    };
  });
}
