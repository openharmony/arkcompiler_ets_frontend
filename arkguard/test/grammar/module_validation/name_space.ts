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

import assert = require('assert');

interface TextValidationRule {
  isValid(text: string): boolean;
}

const alphabeticPattern = /^[A-Za-z]+$/;
const numericPattern = /^[0-9]+$/;

class AlphabeticalValidator implements TextValidationRule {
  isValid(text: string) {
    return alphabeticPattern.test(text);
  }
}

class PostalCodeValidator implements TextValidationRule {
  isValid(text: string) {
    return text.length === 5 && numericPattern.test(text);
  }
}

// Test cases
const testInputs = ["Hello", "98052", "101"];

// Validation registry
const validationRules: { [ruleName: string]: TextValidationRule } = {};
validationRules["Postal Code"] = new PostalCodeValidator();
validationRules["Alphabetical"] = new AlphabeticalValidator();


assert(validationRules["Alphabetical"].isValid(testInputs[0]), 'success');
assert(validationRules["Postal Code"].isValid(testInputs[1]), 'success');
