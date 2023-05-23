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

import {
  factory,
  forEachChild,
  isStringLiteralLike,
  NodeFlags,
} from 'typescript';

import type {
  CallExpression,
  Expression,
  FunctionDeclaration,
  Node,
  ParameterDeclaration,
  ReturnStatement,
  SourceFile, Statement,
  StringLiteralLike,
  VariableDeclaration,
  VariableStatement
} from 'typescript';

import {createStringUnit, EncryptType} from './StringUnit';
import type {StringUnit} from './StringUnit';
import type {IStringOption} from '../../configs/IDataObfuscationOption';
import {Base64Helper} from '../../utils/EncryptedUtils';
import {NodeUtils} from '../../utils/NodeUtils';
import type {INameGenerator} from '../../generator/INameGenerator';

export class SimpleStringObfuscateHelper {
  private stringUnits: Map<string, StringUnit>;

  private stringArray: string[];

  private profile: IStringOption;

  private readonly arrayFuncName: string;

  private readonly indexFuncName: string;

  private readonly mNameGenerator: INameGenerator;

  public constructor(option: IStringOption, generator: INameGenerator) {
    this.profile = option;
    this.stringUnits = new Map<string, StringUnit>();
    this.stringArray = [];
    this.mNameGenerator = generator;
    this.arrayFuncName = this.mNameGenerator.getName();
    this.indexFuncName = this.mNameGenerator.getName();
  }

  public collectLiterals(sourceFile: SourceFile): void {
    let visit = (node: Node): void => {
      if (!isStringLiteralLike(node)) {
        forEachChild(node, visit);
        return;
      }

      // filter octal encode string
      let code: string = NodeUtils.printNode(node, sourceFile);
      const MIN_OCTAL_LEN: number = 3;
      const ZERO_INDEX = 2;
      if (code.length >= MIN_OCTAL_LEN && code[1].startsWith('\\') && code[ZERO_INDEX].startsWith('0')) {
        return;
      }

      // extract all
      let content: string = node.text;
      if (!content) {
        return;
      }

      if (this.stringUnits.has(content)) {
        let unit: StringUnit = this.stringUnits.get(content);
        unit.nodeList.push(node);
      } else {
        let unit: StringUnit = createStringUnit(node);
        if (this.profile.mEncryptType === EncryptType.BASE64) {
          let encrypted: string = new Base64Helper().encode(content);
          if (encrypted) {
            unit.encryptContent = encrypted;
          } else {
            return;
          }
        }

        this.stringArray.push(unit.encryptContent);
        this.stringUnits.set(content, unit);
      }

      forEachChild(node, visit);
    };

    visit(sourceFile);
  }

  public prepareReplaceStruct(literal: StringLiteralLike): Node {
    let stringUnit: StringUnit = this.stringUnits.get(literal.text);
    if (!stringUnit) {
      return literal;
    }

    let index: number = this.stringArray.indexOf(stringUnit.encryptContent);
    if (index < 0) {
      return literal;
    }

    return factory.createCallExpression(
      factory.createIdentifier(this.indexFuncName),
      undefined,
      [factory.createNumericLiteral(index)]
    );
  }

  public prepareArrayFunctionStruct(): FunctionDeclaration {
    let statements: Statement[] = [];

    // string nodes in array
    let arrNodes: Expression[] = [];
    this.stringArray.forEach((element) => {
      arrNodes.push(factory.createStringLiteral(element));
    });

    let arrName: string = this.mNameGenerator.getName();
    let arrStruct: VariableDeclaration = factory.createVariableDeclaration(
      factory.createIdentifier(arrName),
      undefined,
      undefined,
      factory.createArrayLiteralExpression(
        arrNodes,
        true
      )
    );

    let arrFuncStruct: VariableDeclaration = factory.createVariableDeclaration(
      factory.createIdentifier(this.arrayFuncName),
      undefined,
      undefined,
      factory.createFunctionExpression(
        undefined,
        undefined,
        undefined,
        undefined,
        [],
        undefined,
        factory.createBlock(
          [factory.createReturnStatement(factory.createIdentifier(arrName))],
          true
        )
      )
    );

    let declarationStatement: VariableStatement = factory.createVariableStatement(undefined,
      factory.createVariableDeclarationList([arrStruct, arrFuncStruct], NodeFlags.Const));
    statements.push(declarationStatement);

    let callExpr: CallExpression = factory.createCallExpression(
      factory.createIdentifier(this.arrayFuncName),
      undefined,
      []
    );

    let returnStatement: ReturnStatement = factory.createReturnStatement(callExpr);
    statements.push(returnStatement);

    return factory.createFunctionDeclaration(
      undefined,
      undefined,
      undefined,
      factory.createIdentifier(this.arrayFuncName),
      undefined,
      [],
      undefined,
      factory.createBlock(statements, true)
    );
  }

  public prepareIndexFunctionStruct(): FunctionDeclaration {
    let statements: Statement[] = [];
    let indexName: string = this.mNameGenerator.getName();
    let arrName: string = this.mNameGenerator.getName();

    let arrStruct: VariableDeclaration = factory.createVariableDeclaration(
      factory.createIdentifier(arrName),
      undefined,
      undefined,
      factory.createCallExpression(
        factory.createIdentifier(this.arrayFuncName),
        undefined,
        []
      ));

    let indexFuncStruct: VariableDeclaration = factory.createVariableDeclaration(
      factory.createIdentifier(this.indexFuncName),
      undefined,
      undefined,
      factory.createFunctionExpression(
        undefined,
        undefined,
        undefined,
        undefined,
        [factory.createParameterDeclaration(
          undefined,
          undefined,
          undefined,
          factory.createIdentifier(indexName),
          undefined,
          undefined,
          undefined,
        )],
        undefined,
        factory.createBlock(
          [
            factory.createReturnStatement(factory.createElementAccessExpression(
              factory.createIdentifier(arrName),
              factory.createIdentifier(indexName),
            ))
          ]
        )
      )
    );

    let declaration: VariableStatement = factory.createVariableStatement(
      undefined,
      factory.createVariableDeclarationList(
        [
          arrStruct,
          indexFuncStruct,
        ],
        NodeFlags.Const
      ));
    statements.push(declaration);

    let callExpr: CallExpression = factory.createCallExpression(
      factory.createIdentifier(this.indexFuncName),
      undefined,
      [factory.createIdentifier(indexName)]);

    if (this.profile.mEncryptType === EncryptType.BASE64) {
      let decryptName: string = this.mNameGenerator.getName();
      let decryptStruct: Statement = this.prepareDecryptFuncStruct(decryptName);
      statements.push(decryptStruct);
      callExpr = factory.createCallExpression(factory.createIdentifier(decryptName), undefined, [callExpr]);
    }

    let returnStatement: ReturnStatement = factory.createReturnStatement(callExpr);
    statements.push(returnStatement);

    let paramStruct: ParameterDeclaration = factory.createParameterDeclaration(
      undefined,
      undefined,
      undefined,
      factory.createIdentifier(indexName),
      undefined,
      undefined,
      undefined
    );

    return factory.createFunctionDeclaration(
      undefined,
      undefined,
      undefined,
      factory.createIdentifier(this.indexFuncName),
      undefined,
      [paramStruct],
      undefined,
      factory.createBlock(statements, true));
  }

  public isTargetStr(str: string): boolean {
    return this.stringUnits.has(str);
  }

  public prepareDecryptFuncStruct(name: string): Statement {
    let names: string[] = [];

    names.push(name);
    names.push(this.mNameGenerator.getName());
    names.push(this.mNameGenerator.getName());
    names.push(this.mNameGenerator.getName());
    names.push(this.mNameGenerator.getName());
    names.push(this.mNameGenerator.getName());
    names.push(this.mNameGenerator.getName());
    names.push(this.mNameGenerator.getName());
    names.push(this.mNameGenerator.getName());

    return new Base64Helper().decodeStruct(names);
  }
}
