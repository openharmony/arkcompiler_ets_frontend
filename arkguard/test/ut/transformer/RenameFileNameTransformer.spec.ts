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
import { getMangleCompletePath } from '../../../src/transformers/rename/RenameFileNameTransformer';

describe('Tester Cases for <RenameFileNameTransformer>.', function () {
  it('Tester: Test initialization of config in api createRenameFileNameFactory', function () {
    let mCustomProfiles: IOptions | undefined = FileUtils.readFileAsJson(path.join(__dirname, "obfuscate_filename_config.json"));
    assert.strictEqual(mCustomProfiles !== undefined, true);
    let mTransformers: TransformerFactory<Node>[] = [];
    if (mCustomProfiles) {
      mTransformers = new TransformerManager(mCustomProfiles).getTransformers();
    }
    const originalPath = 'D:/workplace/src/ets/entryability/EntryAbility.ts'
    const mangledPath = getMangleCompletePath(originalPath);
    assert.strictEqual(mangledPath === 'D:/workplace/src/ets/a/b.ts', true);
  });
});
