/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as ts from 'typescript';
import { LinterConfig } from '../TypeScriptLinterConfig';
import { forEachNodeInSubtree } from '../utils/functions/ForEachNodeInSubtree';
import { isStructDeclaration } from '../utils/functions/IsStruct';
import type { TsUtils } from '../utils/TsUtils';

export class SymbolCache {
  constructor(
    private readonly typeChecker: ts.TypeChecker,
    private readonly utils: TsUtils,
    readonly sourceFile: ts.SourceFile,
    readonly cancellationToken?: ts.CancellationToken
  ) {
    const callback = (node: ts.Node): void => {
      if (isStructDeclaration(node)) {
        // early exit via exception if cancellation was requested
        this.cancellationToken?.throwIfCancellationRequested();
      }

      const symbol = this.handlersMap.get(node.kind)?.call(this, node);
      if (symbol !== undefined) {
        this.addReference(symbol, node);
      }
    };

    const stopCondition = (node: ts.Node): boolean => {
      return !node || LinterConfig.terminalTokens.has(node.kind);
    };

    forEachNodeInSubtree(sourceFile, callback, stopCondition);
  }

  getReferences(symbol: ts.Symbol): ts.Node[] {
    return this.cache.get(symbol) ?? [];
  }

  private handleElementAccessExpression(node: ts.Node): ts.Symbol | undefined {
    const elementAccessExpr = node as ts.ElementAccessExpression;
    return this.typeChecker.getSymbolAtLocation(elementAccessExpr.argumentExpression);
  }

  private handleEnumDeclaration(node: ts.Node): ts.Symbol | undefined {
    const enumDeclaration = node as ts.EnumDeclaration;
    return this.utils.trueSymbolAtLocation(enumDeclaration.name);
  }

  private handlePrivateIdentifier(node: ts.Node): ts.Symbol | undefined {
    const privateIdentifier = node as ts.PrivateIdentifier;
    return this.typeChecker.getSymbolAtLocation(privateIdentifier);
  }

  private handlePropertyAssignment(node: ts.Node): ts.Symbol | undefined {
    const propertyAssignment = node as ts.PropertyAssignment;
    const contextualType = this.typeChecker.getContextualType(propertyAssignment.parent);
    return contextualType === undefined ? undefined : this.utils.getPropertySymbol(contextualType, propertyAssignment);
  }

  private handlePropertyDeclaration(node: ts.Node): ts.Symbol | undefined {
    const propertyDeclaration = node as ts.PropertyDeclaration;
    return this.typeChecker.getSymbolAtLocation(propertyDeclaration.name);
  }

  private handlePropertySignature(node: ts.Node): ts.Symbol | undefined {
    const propertySignature = node as ts.PropertySignature;
    return this.typeChecker.getSymbolAtLocation(propertySignature.name);
  }

  private handleFunctionDeclaration(node: ts.Node): ts.Symbol | undefined {
    const functionDeclaration = node as ts.FunctionDeclaration;
    return functionDeclaration.name ? this.typeChecker.getSymbolAtLocation(functionDeclaration.name) : undefined;
  }

  private handleCallExpression(node: ts.Node): ts.Symbol | undefined {
    const callExpression = node as ts.CallExpression;
    return this.typeChecker.getSymbolAtLocation(callExpression.expression);
  }

  private handleIdentifier(node: ts.Node): ts.Symbol | undefined {
    const identifier = node as ts.Identifier;
    const symbol = this.typeChecker.getSymbolAtLocation(identifier);
    if (symbol?.flags) {
      return (symbol.flags & ts.SymbolFlags.Variable) !== 0 ? symbol : undefined;
    }
    return undefined;
  }

  private addReference(symbol: ts.Symbol, node: ts.Node): void {
    let nodes = this.cache.get(symbol);
    if (nodes === undefined) {
      nodes = [];
      this.cache.set(symbol, nodes);
    }
    nodes.push(node);
  }

  private readonly handlersMap = new Map([
    [ts.SyntaxKind.ElementAccessExpression, this.handleElementAccessExpression],
    [ts.SyntaxKind.EnumDeclaration, this.handleEnumDeclaration],
    [ts.SyntaxKind.PrivateIdentifier, this.handlePrivateIdentifier],
    [ts.SyntaxKind.PropertyAssignment, this.handlePropertyAssignment],
    [ts.SyntaxKind.PropertyDeclaration, this.handlePropertyDeclaration],
    [ts.SyntaxKind.PropertySignature, this.handlePropertySignature],
    [ts.SyntaxKind.FunctionDeclaration, this.handleFunctionDeclaration],
    [ts.SyntaxKind.CallExpression, this.handleCallExpression],
    [ts.SyntaxKind.Identifier, this.handleIdentifier]
  ]);

  private readonly cache: Map<ts.Symbol, ts.Node[]> = new Map<ts.Symbol, ts.Node[]>();
}
