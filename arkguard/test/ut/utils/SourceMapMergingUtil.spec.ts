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
  Source,
  SourceMapLink
} from '../../../src/utils/SourceMapMergingUtil';
import type {
  ExistingDecodedSourceMap,
  SourceMapSegmentObj
} from '../../../src/utils/SourceMapMergingUtil';
import type { RawSourceMap } from 'typescript';

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

  describe('test for traceMappings' ,function () {
    it('segment.length === 1 && source == true', function () {
      let source: Source = new Source('filename1', 'content1');
      let mappings: ExistingDecodedSourceMap = {
        version: 3,
        sources: ['abc', 'def'],
        mappings: [[[0]]]
      }
      const sourceMapLink = new SourceMapLink(mappings, [source]);
      const tracedMappings = sourceMapLink.traceMappings();
      assert.deepEqual(tracedMappings.mappings, [[]]);
    });

    it('segment.length !== 1 && source == true', function () {
      let source: Source = new Source('filename2', 'content2');
      let mappings: ExistingDecodedSourceMap = {
        version: 3,
        sources: ['abc', 'efg'],
        mappings: [
          [[0]], [[1]]
        ]
      }
      const sourceMapLink = new SourceMapLink(mappings, [source]);
      const tracedMappings = sourceMapLink.traceMappings();
      assert.deepEqual(tracedMappings.mappings, [[], []]);
    });

    it('segment.length === 1 && source == false', function () {
      const source = new Source('example.js', 'console.log("Hello, World!");');
      const mappings: ExistingDecodedSourceMap = {
        version: 3,
        file: 'out.js',
        sources: ['example.js'],
        names: ['console', 'log'],
        mappings: [
          [[0, 5, 0, 0, 1]]
        ],
        sourcesContent: ['sourcesContent1']
      };
      const sourceMapLink = new SourceMapLink(mappings, [source]);
      const tracedMappings = sourceMapLink.traceMappings();
      assert.deepEqual(tracedMappings.mappings, [[]]);
    });

    it('segment.length !== 1 && source == false', function () {
      const source = new Source('example.js', 'console.log("Hello, World!");');
      const mappings: ExistingDecodedSourceMap = {
        version: 3,
        file: 'out.js',
        sources: ['example.js'],
        names: ['console', 'log'],
        mappings: [
          [[0, 5, 0, 0, 1]], [[24]]
        ],
        sourcesContent: ['sourcesContent2']
      };
      const sourceMapLink = new SourceMapLink(mappings, [source]);
      const tracedMappings = sourceMapLink.traceMappings();
      assert.deepEqual(tracedMappings.mappings, [[], []]);
    });
  });

  describe('test for analyzeTracedSource' ,function () {
    let source: Source = new Source('', null);
    let mappings: ExistingDecodedSourceMap = {
      version: 3,
      sources: ['sources'],
      mappings: [[[0]]]
    }
    const sourceMapLink = new SourceMapLink(mappings, [source]);

    it('sourceIndex === undefined', function () {
      const traced: SourceMapSegmentObj = {
        column: 6,
        line: 87,
        name: 'name_abc',
        source: new Source('filename', 'content1')
      }
      const tracedSources: string[] = ['traced', 'sources'];
      const sourceIndexMap: Map<string, number> = new Map();
      const sourcesContent: (string | null)[] = ['sources', 'content'];
      sourceMapLink.analyzeTracedSource(traced, tracedSources, sourceIndexMap, sourcesContent);
      assert.deepEqual(sourceMapLink.mappings, [[[0]]]);
    });

    it('sourcesContent[sourceIndex] == null', function () {
      const traced: SourceMapSegmentObj = {
        column: 34,
        line: 23,
        name: 'name_bcd',
        source: new Source('filename', 'content2')
      }
      const tracedSources: string[] = ['traced', 'sources'];
      const sourceIndexMap: Map<string, number> = new Map();
      sourceIndexMap.set('filename', 1);
      const sourcesContent: (string | null)[] = ['sources'];
      sourceMapLink.analyzeTracedSource(traced, tracedSources, sourceIndexMap, sourcesContent);
      assert.deepEqual(sourceMapLink.mappings, [[[0]]]);
    });

    it('content != null && sourcesContent[sourceIndex] !== content', function () {
      const traced: SourceMapSegmentObj = {
        column: 7,
        line: 65,
        name: 'name_efg',
        source: new Source('filename', 'content3')
      }
      const tracedSources: string[] = ['traced', 'sources'];
      const sourceIndexMap: Map<string, number> = new Map();
      sourceIndexMap.set('filename', 1);
      const sourcesContent: (string | null)[] = ['content3', 'content'];
      assert.throws(() => {
        sourceMapLink.analyzeTracedSource(traced, tracedSources, sourceIndexMap, sourcesContent);
      }, Error, `Multiple conflicting contents for sourcemap source: filename`);
    });
  });

  describe('test for function traceSegment', function () {
    let source: Source = new Source('filename', '// traceSegment');
    let mappings: ExistingDecodedSourceMap = {
      version: 3,
      sources: ['sources', '1', 'xx'],
      mappings: [
        [[0]], [[1, 2, 3, 4, 5]], [[0, 0, 0, 0]]
      ],
      names: ['names1', 'names2', 'names3', 'names4', 'names5']
    }
    const sourceMapLink = new SourceMapLink(mappings, [source]);

    it('segment is false', function (){
      const sourceMapSegmentObj = sourceMapLink.traceSegment(3, 1, 'segment_undefined');
      assert.strictEqual(sourceMapSegmentObj, null);
    });

    it('segments is true && tempSegment.length === 1', function () {
      const sourceMapSegmentObj = sourceMapLink.traceSegment(0, 1, 'segment_one');
      assert.strictEqual(sourceMapSegmentObj, null);
    });

    it('segments is true && source is false', function () {
      const sourceMapSegmentObj = sourceMapLink.traceSegment(1, 0, 'source_false');
      assert.strictEqual(sourceMapSegmentObj, null);
    });

    it('segments is true && source is true', function () {
      const sourceMapSegmentObj = sourceMapLink.traceSegment(2, 0, 'source_true');
      assert.strictEqual(sourceMapSegmentObj?.column, 0);
      assert.strictEqual(sourceMapSegmentObj?.line, 0);
      assert.strictEqual(sourceMapSegmentObj?.name, 'source_true');
      assert.strictEqual(sourceMapSegmentObj?.source.isOriginal, true);
      assert.strictEqual(sourceMapSegmentObj?.source.filename, 'filename');
      assert.strictEqual(sourceMapSegmentObj?.source.content, '// traceSegment');
    });
  });
});
