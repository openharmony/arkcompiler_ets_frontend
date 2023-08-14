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
  isBinaryExpression,
  isCallExpression,
  isClassDeclaration,
  isComputedPropertyName,
  isConstructorDeclaration,
  isEnumDeclaration,
  isIdentifier,
  isObjectLiteralExpression,
  isParameter,
  isPropertyAccessExpression,
  isPropertyAssignment,
  isPropertyDeclaration,
  isStructDeclaration,
  isStringLiteral,
  isTypeLiteralNode,
  isVariableStatement,
  SyntaxKind,
  isExpressionStatement,
  isClassExpression,
} from 'typescript';

import type {
  ClassDeclaration,
  ClassExpression,
  ElementAccessExpression,
  EnumDeclaration,
  Expression,
  HeritageClause,
  InterfaceDeclaration,
  Modifier,
  NodeArray,
  ObjectLiteralExpression,
  PropertyName,
  Statement,
  StructDeclaration,
  TypeAliasDeclaration,
} from 'typescript';

import {OhPackType} from './TransformUtil';

export const stringPropsSet: Set<string> = new Set();
/**
 * find openHarmony module import statement
 * example:
 *  jsbundle - var _ohos = _interopRequireDefault(requireModule('@ohos.hilog'));
 *  esmodule - var hilog = globalThis.requireNapi('hilog') || ...
 *
 * @param node
 * @param moduleName full name of imported module, must check format before called, example:
 *  - '@ohos.hilog'
 *  - '@ohos.application.Ability'
 */
export function findOhImportStatement(node: Statement, moduleName: string): OhPackType {
  if (!isVariableStatement(node) || node.declarationList.declarations.length !== 1) {
    return OhPackType.NONE;
  }

  const initializer: Expression = node.declarationList.declarations[0].initializer;
  if (initializer === undefined) {
    return OhPackType.NONE;
  }

  /** esmodule */
  if (isBinaryExpression(initializer)) {
    if (initializer.operatorToken.kind !== SyntaxKind.BarBarToken) {
      return OhPackType.NONE;
    }

    if (!isCallExpression(initializer.left)) {
      return OhPackType.NONE;
    }

    if (!isPropertyAccessExpression(initializer.left.expression)) {
      return OhPackType.NONE;
    }

    if (!isIdentifier(initializer.left.expression.expression) ||
      initializer.left.expression.expression.text !== 'globalThis') {
      return OhPackType.NONE;
    }

    if (!isIdentifier(initializer.left.expression.name) ||
      initializer.left.expression.name.text !== 'requireNapi') {
      return OhPackType.NONE;
    }

    if (initializer.left.arguments.length !== 1) {
      return OhPackType.NONE;
    }

    const arg: Expression = initializer.left.arguments[0];
    if (isStringLiteral(arg) && arg.text === moduleName.substring('@ohos.'.length)) {
      return OhPackType.ES_MODULE;
    }
  }

  /** jsbundle */
  if (isCallExpression(initializer)) {
    if (initializer.arguments.length !== 1) {
      return OhPackType.NONE;
    }

    if (!isIdentifier(initializer.expression) ||
      initializer.expression.text !== '_interopRequireDefault') {
      return OhPackType.NONE;
    }

    const arg: Expression = initializer.arguments[0];
    if (!isCallExpression(arg)) {
      return OhPackType.NONE;
    }

    if (!isIdentifier(arg.expression) || arg.expression.text !== 'requireModule') {
      return OhPackType.NONE;
    }

    const innerArg: Expression = arg.arguments[0];
    if (!isStringLiteral(innerArg) || innerArg.text !== moduleName) {
      return OhPackType.NONE;
    }

    return OhPackType.JS_BUNDLE;
  }

  return OhPackType.NONE;
}

function containViewPU(heritageClauses: NodeArray<HeritageClause>): boolean {
  if (!heritageClauses) {
    return false;
  }

  let hasViewPU: boolean = false;
  heritageClauses.forEach(
    (heritageClause) => {
      if (!heritageClause || !heritageClause.types) {
        return;
      }

      const types = heritageClause.types;
      types.forEach((typeExpression) => {
        if (!typeExpression || !typeExpression.expression) {
          return;
        }

        const expression = typeExpression.expression;
        if (isIdentifier(expression) && expression.text === 'ViewPU') {
          hasViewPU = true;
        }
      });
    });

  return hasViewPU;
}

/**
 * used to ignore user defined ui component class property name
 * @param classNode
 */
export function isViewPUBasedClass(classNode: ClassDeclaration): boolean {
  if (!classNode) {
    return false;
  }

  if (!isClassDeclaration(classNode)) {
    return false;
  }

  const heritageClause = classNode.heritageClauses;
  return containViewPU(heritageClause);
}

export function collectPropertyNamesAndStrings(memberName: PropertyName, propertySet: Set<string>): void {
  if (isIdentifier(memberName)) {
    propertySet.add(memberName.text);
  }

  if (isStringLiteral(memberName)) {
    propertySet.add(memberName.text);
    stringPropsSet.add(memberName.text);
  }

  if (isComputedPropertyName(memberName) && isStringLiteral(memberName.expression)) {
    propertySet.add(memberName.expression.text);
    stringPropsSet.add(memberName.expression.text);
  }
}

export function getElementAccessExpressionProperties(elementAccessExpressionNode: ElementAccessExpression, propertySet: Set<string>): void {
  if (!elementAccessExpressionNode || !elementAccessExpressionNode.argumentExpression) {
    return;
  }

  if (isStringLiteral(elementAccessExpressionNode.argumentExpression)) {
    stringPropsSet.add(elementAccessExpressionNode.argumentExpression.text);
  }
}

export function getTypeAliasProperties(typeAliasNode: TypeAliasDeclaration, propertySet: Set<string>): void {
  if (!typeAliasNode || !typeAliasNode.type || !isTypeLiteralNode(typeAliasNode.type)) {
    return;
  }

  typeAliasNode.type.members.forEach((member) => {
    if (!member || !member.name) {
      return;
    }
    let memberName: PropertyName = member.name;
    collectPropertyNamesAndStrings(memberName, propertySet);
  });
}

/**
 * export interface interfaceName {
 *  a1: number;
 *  "a2": number;
 *  ["a3"]: number;
 * }
 */

export function getInterfaceProperties(interfaceNode: InterfaceDeclaration, propertySet: Set<string>): void {
  if (!interfaceNode || !interfaceNode.members) {
    return;
  }

  interfaceNode.members.forEach((member) => {
    if (!member || !member.name) {
      return;
    }

    let memberName: PropertyName = member.name;
    collectPropertyNamesAndStrings(memberName, propertySet);
  });
}

function isParameterPropertyModifier(modifier: Modifier): boolean {
  if (modifier.kind === SyntaxKind.PublicKeyword ||
    modifier.kind === SyntaxKind.PrivateKeyword ||
    modifier.kind === SyntaxKind.ProtectedKeyword ||
    modifier.kind === SyntaxKind.ReadonlyKeyword) {
    return true;
  }
  return false;
}

export function getClassProperties(classNode: ClassDeclaration | ClassExpression | StructDeclaration, propertySet: Set<string>): void {
  if (!classNode || !classNode.members) {
    return;
  }

  classNode.members.forEach((member) => {
    if (!member) {
      return;
    }

    const memberName: PropertyName = member.name;
    if (memberName) {
      collectPropertyNamesAndStrings(memberName, propertySet);
    }


    if (isConstructorDeclaration(member) && member.parameters) {
      member.parameters.forEach((parameter) => {
        if (isParameter(parameter) && parameter.modifiers) {
          parameter.modifiers.forEach((modifier) => {
            if (isParameterPropertyModifier(modifier) && parameter.name && isIdentifier(parameter.name)) {
              propertySet.add(parameter.name.text);
            }
          });
          processMemberInitializer(parameter.initializer, propertySet);
        }
      });

      if (member.body) {
        member.body.statements.forEach((statement) => {
          if (isExpressionStatement(statement) && isBinaryExpression(statement.expression) &&
            statement.expression.operatorToken.kind === SyntaxKind.EqualsToken) {
            processMemberInitializer(statement.expression.right, propertySet);
          }
        });
      }
    }

    if (!isPropertyDeclaration(member) || !member.initializer) {
      return;
    }
    processMemberInitializer(member.initializer, propertySet);
  });

  return;
}

function processMemberInitializer(memberInitializer: Expression | undefined, propertySet: Set<string>): void {
  if (!memberInitializer) {
    return;
  }

  if (isObjectLiteralExpression(memberInitializer)) {
    getObjectProperties(memberInitializer, propertySet);
    return;
  }

  if (isClassDeclaration(memberInitializer) || isClassExpression(memberInitializer) || isStructDeclaration(memberInitializer)) {
    getClassProperties(memberInitializer, propertySet);
    return;
  }

  if (isEnumDeclaration(memberInitializer)) {
    getEnumProperties(memberInitializer, propertySet);
    return;
  }
}

export function getEnumProperties(enumNode: EnumDeclaration, propertySet: Set<string>): void {
  if (!enumNode || !enumNode.members) {
    return;
  }

  enumNode.members.forEach((member) => {
    if (!member || !member.name) {
      return;
    }

    const memberName: PropertyName = member.name;
    collectPropertyNamesAndStrings(memberName, propertySet);
    //other kind ignore
  });

  return;
}

export function getObjectProperties(objNode: ObjectLiteralExpression, propertySet: Set<string>): void {
  if (!objNode || !objNode.properties) {
    return;
  }

  objNode.properties.forEach((propertyElement) => {
    if (!propertyElement || !propertyElement.name) {
      return;
    }

    const propertyName: PropertyName = propertyElement.name;
    collectPropertyNamesAndStrings(propertyName, propertySet);

    //extract class element's property, example: export const hello = {info={read: {}}}
    if (!isPropertyAssignment(propertyElement) || !propertyElement.initializer) {
      return;
    }

    if (isObjectLiteralExpression(propertyElement.initializer)) {
      getObjectProperties(propertyElement.initializer, propertySet);
      return;
    }

    if (isClassDeclaration(propertyElement.initializer)) {
      getClassProperties(propertyElement.initializer, propertySet);
      return;
    }

    if (isEnumDeclaration(propertyElement.initializer)) {
      getEnumProperties(propertyElement.initializer, propertySet);
      return;
    }
  });

  return;
}
