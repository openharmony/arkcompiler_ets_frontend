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

import {before} from 'mocha';
import {assert} from 'chai';
import {createSourceFile, ScriptTarget, SourceFile} from 'typescript';

import {collectExistNames, OhPackType} from '../../../src/utils/TransformUtil';
import {findOhImportStatement} from '../../../src/utils/OhsUtil';

describe('test for TransformUtil', function () {
  let sourceFile: SourceFile;

  before('init ast for source file', function () {
    const fileContent = `
    class Demo{
      constructor(public  title: string, public  content: string, public  mark: number) {
          this.title = title
          this.content = content
          this.mark = mark
      }
    }
    `;

    sourceFile = createSourceFile('demo.js', fileContent, ScriptTarget.ES2015, true);
  });

  describe('test for function collectExistNames', function () {
    it('test collectExistNames', function () {
      const nameSets = collectExistNames(sourceFile);
      const targetNames = ['Demo', 'title', 'content', 'mark'];

      assert.strictEqual(nameSets.size, targetNames.length);
      targetNames.forEach((value) => {
        assert.isTrue(nameSets.has(value));
      });
    });
  });

  describe('test for function findOhImportStatement', function () {
    it('find oh import in esmodule', function () {
      const fileContent = `var hilog = globalThis.requireNapi('hilog') ||
     (isSystemplugin('hilog', 'ohos') ?
     globalThis.ohosplugin.hilog : isSystemplugin('hilog', 'system') ?
      globalThis.systemplugin.hilog : undefined);
    `;

      const source = createSourceFile('demo2.js', fileContent, ScriptTarget.ES2015, true);
      const statement = source.statements[0];
      const ohPackType = findOhImportStatement(statement, '@ohos.hilog');

      assert.strictEqual(ohPackType, OhPackType.ES_MODULE);
    });

    it('find oh import in jsbundle', function () {
      const fileContent = `var _ohos = _interopRequireDefault(requireModule('@ohos.hilog'))`;
      const source = createSourceFile('demo2.js', fileContent, ScriptTarget.ES2015, true);
      const statement = source.statements[0];
      const ohPackType = findOhImportStatement(statement, '@ohos.hilog');

      assert.strictEqual(ohPackType, OhPackType.JS_BUNDLE);
    });
  });
});