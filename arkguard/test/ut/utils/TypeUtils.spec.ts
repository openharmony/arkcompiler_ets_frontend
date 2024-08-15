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
import { FileUtils } from '../../../src/utils/FileUtils';
import { Extension, PathAndExtension } from '../../../src/common/type';

describe('test for TypeUtils', function () {
  let sourceFile: SourceFile;
  let jsSourceFile: SourceFile;

  before('init sourceFile', function () {
    const fileContent = `
    //This is a comment
    class Demo{
      constructor(public  title: string, public  content: string, public  mark: number) {
          this.title = title
          this.content = content
          this.mark = mark
      }
    }
    `;
    const jsFileContent = `
    //This is a comment
    class Demo{
      constructor(public  title: string, public  content: string, public  mark: number) {
          this.title = title
          this.content = content
          this.mark = mark
      }
    }
    `;

    sourceFile = createSourceFile('demo.ts', fileContent, ScriptTarget.ES2015, true);
    jsSourceFile = createSourceFile('demo.js', jsFileContent, ScriptTarget.ES2015, true);
  });

  describe('test for method createObfSourceFile', function () {
    it('js test', function () {
      const ast = TypeUtils.createObfSourceFile(jsSourceFile.fileName, jsSourceFile.text);
      const astExtension: PathAndExtension = FileUtils.getFileSuffix(ast.fileName);
      const astFileSuffix = astExtension.ext;

      assert.strictEqual(jsSourceFile.text, ast.text);
      assert.strictEqual(Extension.TS, astFileSuffix);
    });
    it('ts test', function () {
      const ast = TypeUtils.createObfSourceFile(sourceFile.fileName, sourceFile.text);
      const astExtension: PathAndExtension = FileUtils.getFileSuffix(ast.fileName);
      const astFileSuffix = astExtension.ext;

      assert.strictEqual(sourceFile.text, ast.text);
      assert.strictEqual(Extension.TS, astFileSuffix);
    });
  });

  describe('test for function createChecker', function () {
    it('functional test', function () {
      const checker = TypeUtils.createChecker(sourceFile);
      assert.notEqual(checker, undefined);

      const checker1 = TypeUtils.createChecker(jsSourceFile);
      assert.notEqual(checker1, undefined);
    });

    describe('test for function tsToJs', function () {
      it('functional test', function () {
        TypeUtils.tsToJs(sourceFile);
        assert.strictEqual(sourceFile.fileName, 'demo.js');
      });
    });
  });
});