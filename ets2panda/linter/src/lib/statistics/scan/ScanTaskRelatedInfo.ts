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

import type { CommandLineOptions } from '../../CommandLineOptions';
import type { LinterConfig } from '../../LinterConfig';
import type { ProblemInfo } from '../../ProblemInfo';
import type { StatisticsReportInPutInfo } from './StatisticsReportInPutInfo';
import type { TimeRecorder } from './TimeRecorder';

export interface ScanTaskRelatedInfo {
  cmdOptions: CommandLineOptions;
  timeRecorder: TimeRecorder;
  statisticsReportInPutInfo: StatisticsReportInPutInfo;
  mergedProblems: Map<string, ProblemInfo[]>;
  homeCheckResult: Map<string, ProblemInfo[]>;
  totalProblemNumbers: number;
  statisticsReportName: number;
  compileOptions: LinterConfig;
}
