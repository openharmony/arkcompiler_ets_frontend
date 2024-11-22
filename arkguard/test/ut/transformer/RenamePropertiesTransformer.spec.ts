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
import { assert, expect } from 'chai';
import { FileUtils } from '../../../src/utils/FileUtils';
import path from 'path';
import { IOptions } from '../../../src/configs/IOptions';
import fs from 'fs';
import ts, {
  TransformationResult,
  factory,
  transform,
  SourceFile,
  Node,
  IndexedAccessTypeNode,
  LiteralTypeNode,
  setParentRecursive,
  UnionTypeNode
} from 'typescript';
import secharmony from '../../../src/transformers/rename/RenamePropertiesTransformer';
import { ArkObfuscator } from '../../../src/ArkObfuscator';


describe('Tester Cases for <RenamePropertiesTransformer>.', function () {
  describe('Tester Cases for <renameIndexedAccessProperty>.', function () {
    let options: IOptions;
    beforeEach(() => {
      options = {
        mNameObfuscation: {
          mEnable: true,
          mNameGeneratorType: 1,
          mRenameProperties: true,
          mKeepStringProperty: false,
          mReservedProperties: []
        },
      }
    });

    it('should rename string property in indexedAccessType when using prop+strProp', function () {
      ArkObfuscator.isKeptCurrentFile = false;
      const renamePropertiesFactory = secharmony.transformerPlugin.createTransformerFactory(options as IOptions);
      let sourcefile = factory.createIndexedAccessTypeNode(
        factory.createTypeReferenceNode(
          factory.createIdentifier("T"),
          undefined
        ),
        factory.createLiteralTypeNode(factory.createStringLiteral("X"))
      )
      let parentNodes = setParentRecursive(sourcefile, true);
      let transfomedResult: TransformationResult<Node> = transform(parentNodes, [renamePropertiesFactory], {});
      let node = transfomedResult.transformed[0] as IndexedAccessTypeNode;
      expect((node.indexType as LiteralTypeNode).literal).not.to.be.equal((parentNodes.indexType as LiteralTypeNode).literal);
    });

    it('should not rename string property in indexedAccessType when using prop', function () {
      ArkObfuscator.isKeptCurrentFile = false;
      options = {
        mNameObfuscation: {
          mEnable: true,
          mNameGeneratorType: 1,
          mRenameProperties: true,
          mKeepStringProperty: true,
          mReservedProperties: []
        },
      };
      const renamePropertiesFactory = secharmony.transformerPlugin.createTransformerFactory(options as IOptions);
      let sourcefile = factory.createIndexedAccessTypeNode(
        factory.createTypeReferenceNode(
          factory.createIdentifier("T"),
          undefined
        ),
        factory.createLiteralTypeNode(factory.createStringLiteral("X"))
      )
      let parentNodes = setParentRecursive(sourcefile, true);
      let transfomedResult: TransformationResult<Node> = transform(parentNodes, [renamePropertiesFactory], {});
      let node = transfomedResult.transformed[0] as IndexedAccessTypeNode;
      expect((node.indexType as LiteralTypeNode).literal).to.be.equal((parentNodes.indexType as LiteralTypeNode).literal);
    });

    it('should not rename numeric property in indexedAccessType when using prop+strProp', function () {
      ArkObfuscator.isKeptCurrentFile = false;
      options = {
        mNameObfuscation: {
          mEnable: true,
          mNameGeneratorType: 1,
          mRenameProperties: true,
          mKeepStringProperty: false,
          mReservedProperties: []
        },
      };
      const renamePropertiesFactory = secharmony.transformerPlugin.createTransformerFactory(options as IOptions);
      let sourcefile = factory.createIndexedAccessTypeNode(
        factory.createTypeReferenceNode(
          factory.createIdentifier("T"),
          undefined
        ),
        factory.createLiteralTypeNode(factory.createNumericLiteral(1))
      )
      let parentNodes = setParentRecursive(sourcefile, true);
      let transfomedResult: TransformationResult<Node> = transform(parentNodes, [renamePropertiesFactory], {});
      let node = transfomedResult.transformed[0] as IndexedAccessTypeNode;
      expect((node.indexType as LiteralTypeNode).literal).to.be.equal((parentNodes.indexType as LiteralTypeNode).literal);
    });

    it('should rename string property in unionType of indexedAccessType when using prop+strProp', function () {
      ArkObfuscator.isKeptCurrentFile = false;
      options = {
        mNameObfuscation: {
          mEnable: true,
          mNameGeneratorType: 1,
          mRenameProperties: true,
          mKeepStringProperty: false,
          mReservedProperties: []
        },
      };
      const renamePropertiesFactory = secharmony.transformerPlugin.createTransformerFactory(options as IOptions);
      let sourcefile = factory.createIndexedAccessTypeNode(
        factory.createTypeReferenceNode(
          factory.createIdentifier("T"),
          undefined
        ),
        factory.createUnionTypeNode([
          factory.createLiteralTypeNode(factory.createStringLiteral("U")),
          factory.createLiteralTypeNode(factory.createStringLiteral("V"))
        ])
      )
      let parentNodes = setParentRecursive(sourcefile, true);
      let transfomedResult: TransformationResult<Node> = transform(parentNodes, [renamePropertiesFactory], {});
      let node = transfomedResult.transformed[0] as IndexedAccessTypeNode;
      expect(((node.indexType as UnionTypeNode).types[0] as LiteralTypeNode).literal).not.to.be.equal(((parentNodes.indexType as UnionTypeNode).types[0] as LiteralTypeNode).literal);
      expect(((node.indexType as UnionTypeNode).types[1] as LiteralTypeNode).literal).not.to.be.equal(((parentNodes.indexType as UnionTypeNode).types[1] as LiteralTypeNode).literal);
    });

    it('should not rename string property in unionType of indexedAccessType when using prop', function () {
      ArkObfuscator.isKeptCurrentFile = false;
      options = {
        mNameObfuscation: {
          mEnable: true,
          mNameGeneratorType: 1,
          mRenameProperties: true,
          mKeepStringProperty: true,
          mReservedProperties: []
        },
      };
      const renamePropertiesFactory = secharmony.transformerPlugin.createTransformerFactory(options as IOptions);
      let sourcefile = factory.createIndexedAccessTypeNode(
        factory.createTypeReferenceNode(
          factory.createIdentifier("T"),
          undefined
        ),
        factory.createUnionTypeNode([
          factory.createLiteralTypeNode(factory.createStringLiteral("U")),
          factory.createLiteralTypeNode(factory.createStringLiteral("V"))
        ])
      )
      let parentNodes = setParentRecursive(sourcefile, true);
      let transfomedResult: TransformationResult<Node> = transform(parentNodes, [renamePropertiesFactory], {});
      let node = transfomedResult.transformed[0] as IndexedAccessTypeNode;
      expect(((node.indexType as UnionTypeNode).types[0] as LiteralTypeNode).literal).to.be.equal(((parentNodes.indexType as UnionTypeNode).types[0] as LiteralTypeNode).literal);
      expect(((node.indexType as UnionTypeNode).types[1] as LiteralTypeNode).literal).to.be.equal(((parentNodes.indexType as UnionTypeNode).types[1] as LiteralTypeNode).literal);
    });

    it('should not rename numeric property in unionType of indexedAccessType when using prop+strProp', function () {
      ArkObfuscator.isKeptCurrentFile = false;
      options = {
        mNameObfuscation: {
          mEnable: true,
          mNameGeneratorType: 1,
          mRenameProperties: true,
          mKeepStringProperty: false,
          mReservedProperties: []
        },
      };
      const renamePropertiesFactory = secharmony.transformerPlugin.createTransformerFactory(options as IOptions);
      let sourcefile = factory.createIndexedAccessTypeNode(
        factory.createTypeReferenceNode(
          factory.createIdentifier("T"),
          undefined
        ),
        factory.createUnionTypeNode([
          factory.createLiteralTypeNode(factory.createNumericLiteral(1)),
          factory.createLiteralTypeNode(factory.createNumericLiteral(2))
        ])
      )
      let parentNodes = setParentRecursive(sourcefile, true);
      let transfomedResult: TransformationResult<Node> = transform(parentNodes, [renamePropertiesFactory], {});
      let node = transfomedResult.transformed[0] as IndexedAccessTypeNode;
      expect(((node.indexType as UnionTypeNode).types[0] as LiteralTypeNode).literal).to.be.equal(((parentNodes.indexType as UnionTypeNode).types[0] as LiteralTypeNode).literal);
      expect(((node.indexType as UnionTypeNode).types[1] as LiteralTypeNode).literal).to.be.equal(((parentNodes.indexType as UnionTypeNode).types[1] as LiteralTypeNode).literal);
    });
  });
});
