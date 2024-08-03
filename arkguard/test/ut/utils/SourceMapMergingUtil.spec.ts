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

import { assert, expect } from 'chai';
import { before } from 'mocha';
import { 
  decodeSourcemap,
  mergeSourceMap,
  ExistingDecodedSourceMap,
  Source,
  SourceMapLink
} from '../../../src/utils/SourceMapMergingUtil';
import { RawSourceMap } from 'typescript';

describe('test for SourceMapMergingUtil', function () {
  it('test the sourcemap merging', function () {
    /**
     * // source ts code:
     * function foo(){
     *   console.log("hello world");
     *   return 1;
     * }
     */
    const previousMap = {
      "version": 3,
      "file": "index.js",
      "sources": [
        "index.ts"
      ],
      "names": [],
      "mappings": "AAAA,SAAS,GAAG;IACV,OAAO,CAAC,GAAG,CAAC,aAAa,CAAC,CAAC;IAC3B,OAAO,CAAC,CAAC;AACX,CAAC",
      "sourceRoot": "",
    }
    /**
     * // transformed ts code:
     * function foo() {
     *     console.log("hello world");
     *     return 1;
     * }
     */
    const currentMap = {
      "version": 3,
      "file": "index.js",
      "sources": [
        "index.js"
      ],
      "names": [],
      "mappings": "AAAA;IAEI,OAAO,CAAC,CAAC;CACZ",
      "sourceRoot": "",
    }
    /** 
     * // obfuscated code:
     * function a(){
     *     return 1;
     * }
     */
    const actual = mergeSourceMap(previousMap as RawSourceMap, currentMap as RawSourceMap);
    const expect = '{"version":3,"file":"index.js","sources":["index.ts"],"names":[],"mappings":"AAAA;IAEE,OAAO,CAAC,CAAC;CACV","sourceRoot":""}'
    assert.isTrue(JSON.stringify(actual) === expect);
  });

  describe('test for SourceMapLink', function () {
    let source: Source;
    let mappings: ExistingDecodedSourceMap;

    before(() => {
      source = new Source('example.js', 'console.log("Hello, World!");');
      mappings = {
        version: 3,
        file: 'out.js',
        sources: ['example.js'],
        names: ['console', 'log'],
        mappings: [
          [[0, 0, 0, 0, 1]]
        ],
        sourcesContent: [],
      };
    });

    it('should trace mappings correctly', () => {
      const sourceMapLink = new SourceMapLink(mappings, [source]);
      const traced = sourceMapLink.traceMappings();

      expect(traced.mappings).to.have.lengthOf(1);
      expect(traced.names).to.include('log');
      expect(traced.sources).to.include('example.js');
    });
  });

  describe('test for decodeSourcemap', function () {
    it('should return null for null map', () => {
      const result = decodeSourcemap(null);
      expect(result).to.be.null;
    });

    it('should return empty mappings for empty mappings string', () => {
      const map: RawSourceMap = {
        version: 3,
        file: 'out.js',
        sources: ['example.js'],
        names: [],
        mappings: '', // Empty mappings
        sourcesContent: ['Hello, World!'],
      };

      const result = decodeSourcemap(map);
      expect(result).to.deep.equal({
        names: [],
        mappings: [],
        sources: [],
        version: 3
      });
    });
  });
});
