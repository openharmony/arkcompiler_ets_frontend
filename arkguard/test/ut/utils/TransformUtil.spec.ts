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

import {
  collectExistNames,
  wildcardTransformer
} from '../../../src/utils/TransformUtil';

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

  describe('test for function wildcardTransformer', function () {
    it('test wildcardTransformer', function () {
      // special characters: '\', '^', '$', '.', '+', '|', '[', ']', '{', '}', '(', ')'
      const reserved1 = 'a\\+b*';
      const reserved2 = '{*}[*](*)';
      const reserved3 = '*^';
      const reserved4 = '?$\\..';
      const reserved5 = '?|123';

      const result1 = wildcardTransformer(reserved1);
      const result2 = wildcardTransformer(reserved2);
      const result3 = wildcardTransformer(reserved3);
      const result4 = wildcardTransformer(reserved4);
      const result5 = wildcardTransformer(reserved5);

      assert.strictEqual(result1, String.raw`a\\\+b.*`);
      assert.strictEqual(result2, String.raw`\{.*\}\[.*\]\(.*\)`);
      assert.strictEqual(result3, String.raw`.*\^`);
      assert.strictEqual(result4, String.raw`.\$\\\.\.`);
      assert.strictEqual(result5, String.raw`.\|123`);
    });
  });
});