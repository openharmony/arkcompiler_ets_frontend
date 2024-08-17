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

import {describe, it} from 'mocha';
import {expect} from 'chai';
import {FileUtils} from '../../../src/utils/FileUtils';
import {
  writeCache,
  spaceOfNameCache,
  readCache,
  getMapFromJson,
  deleteLineInfoForNameString,
  UpdateMemberMethodName,
  MEM_METHOD_CACHE
} from '../../../src/utils/NameCacheUtil';

describe('test for NameCacheUtils', () => {
  const destFileName = 'test/ut/utils/testWriteReadCache.json';

  describe('writeCache', () => {
    it('should write cache to file', function () {
      const cache = new Map([
        ['key1', 'value1'],
        ['key2', 'value2'],
      ]);

      writeCache(cache, destFileName);

      const content = FileUtils.readFile(destFileName);
      expect(content).to.equal(JSON.stringify({ key1: 'value1', key2: 'value2' }, null, spaceOfNameCache));
      FileUtils.deleteFile(destFileName);
    });

    it('should not write if cache is empty', function () {
      const cache = undefined;

      writeCache(cache, destFileName);

      const content = FileUtils.readFile(destFileName);
      expect(content).to.be.undefined;
      FileUtils.deleteFile(destFileName);
    });
  });

  describe('readCache', () => {
    it('should return undefined when file does not exist', () => {
      const result = readCache(destFileName);
      expect(result).to.be.undefined;
    });

    it('should return parsed JSON object when file exists', () => {
      const testData = { key: 'value' };
      FileUtils.writeFile(destFileName, JSON.stringify(testData));

      const result = readCache(destFileName);
      expect(result).to.deep.equal(testData);

      FileUtils.deleteFile(destFileName);
    });
  });

  describe('getMapFromJson', () => {
    it('should return an empty Map when input is undefined', () => {
      const result = getMapFromJson(undefined);
      expect(result).to.be.an.instanceof(Map);
      expect(result.size).to.equal(0);
    });

    it('should convert a JSON object to a Map with string keys and values', () => {
      const jsonObj = { key1: 'value1', key2: 'value2' };
      const expectedMap = new Map([
        ['key1', 'value1'],
        ['key2', 'value2']
      ]);
      const result = getMapFromJson(jsonObj);
      expect(result).to.deep.equal(expectedMap);
    });
  });

  describe('deleteLineInfoForNameString', () => {
    it('should update historyNameCache with new keys from identifierCache', () => {
      const historyNameCache = new Map([
        ['#key1', 'value1'],
        ['#key2', 'value2']
      ]);
      const identifierCache = {
        '#key3:112:110': 'newValue3',
        '#key4': 'newValue4'
      };

      deleteLineInfoForNameString(historyNameCache, identifierCache);

      expect(historyNameCache.get('#key1')).to.equal('value1');
      expect(historyNameCache.get('#key2')).to.equal('value2');
      expect(historyNameCache.get('#key3')).to.equal('newValue3');
      expect(historyNameCache.get('#key4')).to.equal('newValue4');
    });

    it('should not modify historyNameCache if identifierCache is undefined', () => {
      const historyNameCache = new Map([
        ['#key1:11:2', 'value1'],
        ['#key2:11:3', 'value2']
      ]);

      deleteLineInfoForNameString(historyNameCache, undefined);

      expect(historyNameCache.get('#key1:11:2')).to.equal('value1');
      expect(historyNameCache.get('#key2:11:3')).to.equal('value2');
    });
  });

  describe('UpdateMemberMethodName', () => {
    it('should update member method names in the cache', () => {
      const nameCache = new Map();
      const globalMangledTable = new Map([['originalName', 'mangledName']]);
      const classInfoInMemberMethodCache = new Set(['class1']);

      nameCache.set(MEM_METHOD_CACHE, new Map([['method1', 'originalName']]));

      UpdateMemberMethodName(nameCache, globalMangledTable, classInfoInMemberMethodCache);

      const updatedMemberMethodCache = nameCache.get(MEM_METHOD_CACHE) as Map<string, string>;
      expect(updatedMemberMethodCache.get('method1')).to.equal('mangledName');
    });

    it('should not update member method names if they are in classInfoInMemberMethodCache', () => {
      const nameCache = new Map();
      const globalMangledTable = new Map([['originalName', 'mangledName']]);
      const classInfoInMemberMethodCache = new Set(['method1']);

      nameCache.set(MEM_METHOD_CACHE, new Map([['method1', 'originalName']]));

      UpdateMemberMethodName(nameCache, globalMangledTable, classInfoInMemberMethodCache);

      const updatedMemberMethodCache = nameCache.get(MEM_METHOD_CACHE) as Map<string, string>;
      expect(updatedMemberMethodCache.get('method1')).to.equal('originalName');
    });

    it('do nothing if we do not set MEM_METHOD_CACHE', () => {
      const nameCache = new Map();
      const globalMangledTable = new Map([['originalName', 'mangledName']]);
      const classInfoInMemberMethodCache = new Set(['method1']);

      nameCache.set('testKey', new Map([['method1', 'originalName']]));

      UpdateMemberMethodName(nameCache, globalMangledTable, classInfoInMemberMethodCache);

      const updatedMemberMethodCache = nameCache.get('testKey') as Map<string, string>;
      expect(updatedMemberMethodCache.get('method1')).to.equal('originalName');
    });
  });
})