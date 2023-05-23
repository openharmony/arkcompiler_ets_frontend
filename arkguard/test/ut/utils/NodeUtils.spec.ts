/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {before, describe} from 'mocha';
import {assert} from 'chai';
import {createSourceFile, ScriptTarget, SourceFile} from 'typescript';
import {NodeUtils} from '../../../src/utils/NodeUtils';

describe('test for NodeUtils', function () {
  let fileContent;
  let sourceFile: SourceFile;

  before('init ast for source file', function () {
    fileContent = `
      function sayHello2() {
      let student = 'Dudu';
      var _c111 = '3|1|2|4|0'.split('|'), _ddd = [3,1,2,0,4], _0x67e02af2_ = 0;
      for (;;) {
          switch (_c111[_ddd[_0x67e02af2_++]]) {
              case '0':
                  console.log('when ' + student);
                  continue;
              case '1':
                  console.log('where ' + student);
                  continue;
              case '2':
                  console.log('how ' + student);
                  continue;
              case '3':
                  console.log('what ' + student);
                  continue;
              case '4':
                  console.log('hello ' + student);
                  continue;
          }
          break;
      }
    }
    
    for (;;) {}
    sayHello2();
    `;

    sourceFile = createSourceFile('demo.js', fileContent, ScriptTarget.ES2015, true);
  });

  describe('test for printNode', function () {
    it('functional test', function () {
      const printedContent = NodeUtils.printNode(sourceFile, sourceFile);

      const originRemoved = fileContent.replace(/\n/g, '').replace(/\r/g, '').replace(/ /g, '');
      const printedRemoved = printedContent.replace(/\n/g, '').replace(/\r/g, '').replace(/ /g, '');

      assert.equal(originRemoved, printedRemoved);
    });
  });

  describe('test for method isLoopStatement', function () {
    it('functional test', function () {
      assert.isTrue(NodeUtils.isLoopStatement(sourceFile.statements[1]));
    });
  });
});