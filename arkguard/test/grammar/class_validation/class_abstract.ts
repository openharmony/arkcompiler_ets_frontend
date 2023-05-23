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

abstract class Department {

  constructor(public name: string) {
  }

  printName(): string {
    return this.name;
  }

  abstract getMeeting(): string;
}

class AccountingDepartment extends Department {

  constructor() {
    super('Accounting and Auditing');
  }

  getMeeting(): string {
    return 'We meet as 10am!';
  }

  generateReports(): void {
    console.log('Generating accounting reports...');
  }
}

let department: Department;
department = new AccountingDepartment();

assert(department.printName() === 'Accounting and Auditing', 'success');
assert(department.getMeeting() === 'We meet as 10am!', 'success');