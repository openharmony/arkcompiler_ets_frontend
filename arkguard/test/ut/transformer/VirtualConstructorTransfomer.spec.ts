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
import { expect, assert } from 'chai';
import { IOptions } from '../../../src/configs/IOptions';
import ts, {
    TransformerFactory,
    Node,
    TransformationContext,
    factory,
    SyntaxKind,
    CallExpression,
    Expression,
    CompilerOptions,
    EmitHelper,
    EmitHint,
    FunctionDeclaration,
    Identifier,
    Statement,
    SourceFile,
    VariableDeclaration,
  } from 'typescript';
import { NodeUtils } from '../../../src/utils/NodeUtils';
import path from 'path';
import secharmony from '../../../src/transformers/rename/VirtualConstructorTransformer';

describe('Tester Cases for <virtualConstructorTransformerFactory>.', function () {
  let options: IOptions;
  let context: TransformationContext = {
    requestEmitHelper: function (helper: EmitHelper): void {},
    readEmitHelpers: function (): EmitHelper[] | undefined {
      return undefined;
    },
    enableSubstitution: function (kind: SyntaxKind): void {},
    isSubstitutionEnabled: function (node: Node): boolean {
      throw new Error('Function not implemented.');
    },
    onSubstituteNode: function (hint: EmitHint, node: Node): Node {
      throw new Error('Function not implemented.');
    },
    enableEmitNotification: function (kind: SyntaxKind): void {},
    isEmitNotificationEnabled: function (node: Node): boolean {
      throw new Error('Function not implemented.');
    },
    onEmitNode: function (hint: EmitHint, node: Node, emitCallback: (hint: EmitHint, node: Node) => void): void {
      throw new Error('Function not implemented.');
    },
    factory: ts.factory,
    getCompilerOptions: function (): CompilerOptions {
      throw new Error('Function not implemented.');
    },
    startLexicalEnvironment: function (): void {},
    suspendLexicalEnvironment: function (): void {},
    resumeLexicalEnvironment: function (): void {},
    endLexicalEnvironment: function (): Statement[] | undefined {
      return undefined;
    },
    hoistFunctionDeclaration: function (node: FunctionDeclaration): void {},
    hoistVariableDeclaration: function (node: Identifier): void {}
  };

  describe('Tester Cases for <virtualConstructorTransformerFactory>.', function () {
    it('should return virtualConstructorTransformer', function () {
        const transfomerFactory = secharmony.transformerPlugin.createTransformerFactory(options);
        expect(transfomerFactory).to.not.be.undefined;
    });
  });

  describe('Tester Cases for <virtualConstructorTransformer>.', function () {
    it('should return node if is not DETSFile', function () {
      const sourceCode = `let a:number = 1;`;
      let sourcefile = ts.createSourceFile("a.ts", sourceCode, ts.ScriptTarget.ES2022, false);
      const transfomerFactory = secharmony.transformerPlugin.createTransformerFactory(options);
      const node = transfomerFactory(context)(sourcefile);
      expect(node).to.be.equal(sourcefile);
    });

    it('should return node if is DETSFile but not StructDeclaration', function () {
      const sourceCode = `let a:number = 1;`;
      let sourcefile = ts.createSourceFile("a.d.ets", sourceCode, ts.ScriptTarget.ES2022, false);
      const transfomerFactory = secharmony.transformerPlugin.createTransformerFactory(options);
      const node = transfomerFactory(context)(sourcefile);
      expect(node).to.be.equal(sourcefile);
    });

    it('should return update node if is StructDeclaration', function () {
      const sourceCode = `struct Demo{ };`;
      let sourcefile = ts.createSourceFile("a.d.ets", sourceCode, ts.ScriptTarget.ES2022, false);
      const transfomerFactory = secharmony.transformerPlugin.createTransformerFactory(options);
      const node = transfomerFactory(context)(sourcefile);
      expect(node).to.not.be.equal(sourcefile);
    });
  });
});