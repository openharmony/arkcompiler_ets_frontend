/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import * as yup from 'yup';
import type { Autofix } from '../lib/autofixes/Autofixer';

const TAB = '    ';

export interface TestResult {
  result: TestProblemInfo[];
}

export interface TestProblemInfo {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  problem: string;
  suggest: string;
  rule: string;
  severity: string;
  exclusive?: string;
  autofix?: Autofix[];
}

const autofixResultSchema: yup.ObjectSchema<Autofix> = yup.object({
  replacementText: yup.string().defined(),
  start: yup.number().required(),
  end: yup.number().required(),
  line: yup.number().optional(),
  column: yup.number().optional(),
  endLine: yup.number().optional(),
  endColumn: yup.number().optional()
});

const testResultSchema: yup.ObjectSchema<TestResult> = yup.object({
  result: yup.
    array(
      yup.object({
        line: yup.number().required(),
        column: yup.number().required(),
        endLine: yup.number().required(),
        endColumn: yup.number().required(),
        problem: yup.string().required(),
        suggest: yup.string().defined(),
        rule: yup.string().required(),
        severity: yup.string().required(),
        exclusive: yup.string(),
        autofix: yup.array(autofixResultSchema)
      })
    ).
    required()
});

export function validateTestResult(value: object): TestResult {
  try {
    return testResultSchema.validateSync(value, { strict: true, abortEarly: false });
  } catch (error) {
    if (error instanceof yup.ValidationError) {
      let errMsg = '';
      for (const msg of error.errors) {
        errMsg += '\n' + TAB + TAB + msg;
      }
      throw new Error(errMsg);
    }
    throw error;
  }
}
