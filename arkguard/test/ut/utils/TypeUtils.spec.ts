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

import {assert} from 'chai';
import {before, describe} from 'mocha';
import {createSourceFile, ScriptTarget, SourceFile} from 'typescript';

import {TypeUtils} from '../../../src/utils/TypeUtils';

describe('test for TypeUtils', function () {
  let sourceFile: SourceFile;

  before('init sourceFile', function () {
    const fileContent = `
    class Demo{
      constructor(public  title: string, public  content: string, public  mark: number) {
          this.title = title
          this.content = content
          this.mark = mark
      }
    }
    `;

    sourceFile = createSourceFile('demo.ts', fileContent, ScriptTarget.ES2015, true);
  });

  describe('test for method createNewSourceFile', function () {
    it('functional test', function () {
      const newSource = TypeUtils.createNewSourceFile(sourceFile);

      assert.strictEqual(sourceFile.statements.length, newSource.statements.length);
      assert.notStrictEqual(sourceFile.fileName, newSource.fileName);
      assert.isTrue(newSource.fileName.endsWith('.ts'));
    });
  });

  describe('test for function createChecker', function () {
    it('functional test', function () {
      const checker = TypeUtils.createChecker(sourceFile);
      assert.notEqual(checker, undefined);
    });
  });
});