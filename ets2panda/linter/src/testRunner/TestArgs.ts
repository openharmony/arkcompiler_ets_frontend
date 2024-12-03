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

const TAB = '    ';

/**
 * Describes test configuration format for [test.args.json] file.
 */
export interface TestArguments {

  /**
   * Common arguments applied to each test mode. Will be overriden
   * by arguments specified for a certain mode.
   */
  commonArgs?: string;

  /**
   * Specifies the test modes. If omitted, test will run only in 'default' mode.
   *
   * To 'enable' a certain mode for a test, specify corresponding property
   * in the 'mode' property. Each mode creates additional test result file
   * with corresponding extension.
   *
   * Additional arguments may be provided to a certain mode with a string value.
   * Empty string means no additional arguments.
   */
  mode?: {

    /**
     * Optional property that can be used to specify additional arguments
     * for default mode. Test will run in default mode regardless
     * of whether this property is specified.
     */
    default?: string;

    /**
     * Enables 'autofix' mode, runs test with '--autofix' option.
     * Adds generated autofix suggestions in test result file.
     */
    autofix?: string;

    /**
     * Enables 'ArkTS 2.0' mode, runs test with '--arkts-2' option.
     */
    arkts2?: string;
  };
}

const testArgsSchema: yup.ObjectSchema<TestArguments> = yup.object({
  commonArgs: yup.string(),
  mode: yup.
    object({
      default: yup.string(),
      autofix: yup.string(),
      arkts2: yup.string()
    }).
    optional()
});

export function validateTestArgs(value: object): TestArguments {
  try {
    return testArgsSchema.validateSync(value, { strict: true, abortEarly: false });
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
