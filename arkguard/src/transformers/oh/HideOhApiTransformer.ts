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
  isBlock,
  isElementAccessExpression,
  isPropertyAccessExpression,
  isSourceFile,
  isStringLiteral,
  setParentRecursive,
  visitEachChild
} from 'typescript';

import type {
  Block,
  CallExpression,
  Node,
  NodeArray,
  SourceFile,
  Statement,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import type {IOptions} from '../../configs/IOptions';
import type {TransformPlugin} from '../TransformPlugin';
import {collectExistNames, OhPackType} from '../../utils/TransformUtil';
import {findOhImportStatement} from '../../utils/OhsUtil';
import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';

namespace secharmony {
  const TRANSFORMER_ORDER: number = 3;
  export let transformerPlugin: TransformPlugin = {
    'name': 'hideOhApiPlugin',
    'order': (1 << TRANSFORMER_ORDER),
    'createTransformerFactory': createHideOhApiFactory
  };

  interface OhHiddenApiInfo {
    moduleNames: Set<string>,
    apis: Set<string>
  }

  export function createHideOhApiFactory(option: IOptions): TransformerFactory<Node> {
    if (!option.mHideOhApi || !option.mHideOhApi.mEnable) {
      return null;
    }

    if (!option.mHideOhApi.mProtectedApi || option.mHideOhApi.mProtectedApi.length < 1) {
      return null;
    }

    return hideOhApiFactory;

    function hideOhApiFactory(context: TransformationContext): Transformer<Node> {
      let nameGenerator: INameGenerator;
      let ohHiddenApiInfo: OhHiddenApiInfo;

      return transformer;

      function transformer(node: Node): Node {
        if (!isSourceFile(node) || node.fileName.endsWith('.d.ts')) {
          return node;
        }

        const reservedIdentifiers: Set<string> = collectExistNames(node);
        const options: NameGeneratorOptions = {
          reservedNames: reservedIdentifiers
        };
        nameGenerator = getNameGenerator(NameGeneratorType.ORDERED, options);

        ohHiddenApiInfo = processOhApi(option.mHideOhApi.mProtectedApi);

        let resultAst: Node = visitAst(node);
        return setParentRecursive(resultAst, true);
      }

      function visitAst(node: Node): Node {
        if (isSourceFile(node)) {
          const hiddenNode: SourceFile = visitEachChild(node, visitAst, context);
          const newStatements: Statement[] = hideStatements(hiddenNode.statements, nameGenerator, ohHiddenApiInfo, context);
          return factory.updateSourceFile(hiddenNode, newStatements);
        }

        if (isBlock(node)) {
          const hiddenNode: Block = visitEachChild(node, visitAst, context);
          const newStatements: Statement[] = hideStatements(hiddenNode.statements, nameGenerator, ohHiddenApiInfo, context);
          if (newStatements === undefined) {
            return hiddenNode;
          }

          return factory.createBlock(newStatements, true);
        }

        return visitEachChild(node, visitAst, context);
      }
    }
  }

  function hideStatements(statements: NodeArray<Statement>, nameGenerator: INameGenerator, ohHiddenApiInfo: OhHiddenApiInfo,
    context: TransformationContext): Statement[] {
    let newStatements: Statement[] = [...statements];
    const apiHiddenMap: Map<string, string> = new Map<string, string>();

    for (let i = 0; i < statements.length; i++) {
      // 1. hide api import
      for (const module of ohHiddenApiInfo.moduleNames) {
        const ohPackType: OhPackType = findOhImportStatement(statements[i], module);
        if (ohPackType === OhPackType.NONE) {
          continue;
        }

        const moduleStr: string = ohPackType === OhPackType.JS_BUNDLE ? module : module.substring('@ohos.'.length);
        const hiddenFuncName: string = nameGenerator.getName();
        const hiddenStatement: Statement = createHiddenStatement(hiddenFuncName, moduleStr);

        newStatements[i] = hideOhStr(statements[i], hiddenFuncName, moduleStr, context);
        newStatements.push(hiddenStatement);
        break;
      }

      // 2. hide api
      newStatements[i] = hideOhApi(newStatements[i], ohHiddenApiInfo.apis, nameGenerator, context, apiHiddenMap);
    }

    for (const key of apiHiddenMap.keys()) {
      newStatements.push(createHiddenStatement(apiHiddenMap.get(key), key));
    }

    return newStatements;
  }

  function hideOhStr(node: Statement, hiddenFuncName: string, hiddenStr: string, context: TransformationContext): Statement {
    let visit = (node: Node): Node => {
      if (isStringLiteral(node) && node.text === hiddenStr) {
        return factory.createCallExpression(factory.createIdentifier(hiddenFuncName), undefined, []);
      }

      return visitEachChild(node, visit, context);
    };

    return visit(node) as Statement;
  }

  function hideOhApi(node: Statement, apiNames: Set<string>, nameGenerator: INameGenerator, context: TransformationContext, apiHiddenMap): Statement {
    let visit = (node: Node): Node => {
      if (isBlock(node)) {
        return node;
      }

      if (isPropertyAccessExpression(node)) {
        if (!apiNames.has(node.name.text)) {
          return node;
        }

        const hiddenFuncName: string = apiHiddenMap.has(node.name.text) ?
          apiHiddenMap.get(node.name.text) : nameGenerator.getName();
        if (!apiHiddenMap.has(node.name.text)) {
          apiHiddenMap.set(node.name.text, hiddenFuncName);
        }

        const hiddenCall: CallExpression = factory.createCallExpression(
          factory.createIdentifier(hiddenFuncName),
          undefined,
          []
        );
        return factory.createElementAccessExpression(node.expression, hiddenCall);
      }

      if (isElementAccessExpression(node)) {
        if (!isStringLiteral(node.argumentExpression)) {
          return node;
        }

        if (!apiNames.has(node.argumentExpression.text)) {
          return node;
        }

        const hiddenFuncName: string = apiHiddenMap.has(node.argumentExpression.text) ?
          apiHiddenMap.get(node.argumentExpression.text) : nameGenerator.getName();
        if (!apiHiddenMap.has(node.argumentExpression.text)) {
          apiHiddenMap.set(node.argumentExpression.text, hiddenFuncName);
        }

        const hiddenCall: CallExpression = factory.createCallExpression(
          factory.createIdentifier(hiddenFuncName),
          undefined,
          []);
        return factory.createElementAccessExpression(node.expression, hiddenCall);
      }

      return visitEachChild(node, visit, context);
    };

    return visit(node) as Statement;
  }

  /**
   * process api list to get module and api function
   * @param apiList
   * @private
   */
  function processOhApi(apiList: string[]): OhHiddenApiInfo {
    let apiInfo: OhHiddenApiInfo = {
      moduleNames: new Set<string>(),
      apis: new Set<string>()
    };

    for (const api of apiList) {
      // check format
      const MIN_OFFSET = 2;
      if (!api.startsWith('@ohos') || !api.includes('.') || api.lastIndexOf('.') > api.length - MIN_OFFSET) {
        continue;
      }

      // extract api
      apiInfo.moduleNames.add(api.substring(0, api.lastIndexOf('.')));
      apiInfo.apis.add(api.substring(api.lastIndexOf('.') + 1));
    }

    return apiInfo;
  }

  function createHiddenStatement(hiddenFuncName: string, hiddenStr: string): Statement {
    return factory.createFunctionDeclaration(
      undefined,
      undefined,
      undefined,
      factory.createIdentifier(hiddenFuncName),
      undefined,
      [],
      undefined,
      factory.createBlock(
        [
          factory.createReturnStatement(factory.createStringLiteral(hiddenStr))
        ], false
      )
    );
  }
}

export = secharmony;
