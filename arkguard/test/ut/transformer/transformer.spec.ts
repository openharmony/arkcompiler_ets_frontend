/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import { describe, it } from 'mocha';
import { TransformerManager } from '../../../src/transformers/TransformerManager';
import { assert } from 'chai';
import { FileUtils } from '../../../src/utils/FileUtils';
import path from 'path';
import { IOptions } from '../../../src/configs/IOptions';
import { TransformerFactory, Node } from 'typescript';

describe('Tester Cases for <FileUtils>.', function () {
  it('Tester: loade transformers for obfuscation config', function () {
    let mCustomProfiles: IOptions | undefined = FileUtils.readFileAsJson(path.join(__dirname, "default_config.json"));
    assert.strictEqual(mCustomProfiles !== undefined, true);
    let mTransformers: TransformerFactory<Node>[] = [];
    if (mCustomProfiles) {
      mTransformers = new TransformerManager(mCustomProfiles).getTransformers();
      assert.strictEqual(mTransformers.length, 3);
      assert.strictEqual(mTransformers.toString().includes('shorthandPropertyTransformFactory'), true);
      assert.strictEqual(mTransformers.toString().includes('renameIdentifierFactory'), true);
      assert.strictEqual(mTransformers.toString().includes('renamePropertiesFactory'), false);
    }

    mCustomProfiles = FileUtils.readFileAsJson(path.join(__dirname, "property_obf_config.json"));
    assert.strictEqual(mCustomProfiles !== undefined, true);
    if (mCustomProfiles) {
      mTransformers = new TransformerManager(mCustomProfiles).getTransformers();
      assert.strictEqual(mTransformers.length, 4);
      assert.strictEqual(mTransformers.toString().includes('shorthandPropertyTransformFactory'), true);
      assert.strictEqual(mTransformers.toString().includes('renameIdentifierFactory'), true);
      assert.strictEqual(mTransformers.toString().includes('renamePropertiesFactory'), true);
    }
  });
});
