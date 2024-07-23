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
import {
  getMangleCompletePath,
  handleNormalizedOhmUrl
} from '../../../src/transformers/rename/RenameFileNameTransformer';

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

  it('Tester: Test Api handleNormalizedOhmUrl', function () {
    let ohmUrl1 = '@normalized:N&&&entry/src/main/ets/pages/test&';
    let ohmUrl2 = '@normalized:N&&&library/Index&1.0.0';
    let ohmUrl3 = '@normalized:N&&&@abc/a/src/main/ets/pages/test&';

    let pkgname1 = handleNormalizedOhmUrl(ohmUrl1, true);
    let pkgname2 = handleNormalizedOhmUrl(ohmUrl2, true);
    let pkgname3 = handleNormalizedOhmUrl(ohmUrl3, true);

    assert.strictEqual(pkgname1, 'entry');
    assert.strictEqual(pkgname2, 'library');
    assert.strictEqual(pkgname3, '@abc/a');

    let mangledOhmurl1 = handleNormalizedOhmUrl(ohmUrl1);
    let mangledOhmurl2 = handleNormalizedOhmUrl(ohmUrl2);
    let mangledOhmurl3 = handleNormalizedOhmUrl(ohmUrl3);

    assert.strictEqual(mangledOhmurl1, '@normalized:N&&&entry/src/c/ets/d/e&');
    assert.strictEqual(mangledOhmurl2, '@normalized:N&&&library/f&1.0.0');
    assert.strictEqual(mangledOhmurl3, '@normalized:N&&&@abc/a/src/c/ets/d/e&');
  });
});
