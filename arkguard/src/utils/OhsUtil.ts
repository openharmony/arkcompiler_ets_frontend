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
  isIdentifier,
  isPropertyAccessExpression,
  isStringLiteral,
  isVariableStatement,
  SyntaxKind,
  isPropertyDeclaration,
  isObjectLiteralExpression,
  isEnumDeclaration,
  isPropertyAssignment,
  StructDeclaration,
  isStructDeclaration
} from 'typescript';

import type {
  ClassDeclaration,
  ClassExpression,
  EnumDeclaration,
  Expression,
  HeritageClause,
  NodeArray,
  ObjectLiteralExpression,
  Statement
} from 'typescript';

import {OhPackType} from './TransformUtil';

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

export function getClassProperties(classNode: ClassDeclaration | ClassExpression | StructDeclaration, propertySet: Set<string>): void {
  if (!classNode || !classNode.members) {
    return;
  }

  classNode.members.forEach((member) => {
    if (!member || !member.name) {
      return;
    }

    if (isIdentifier(member.name)) {
      propertySet.add(member.name.text);
    }

    if (isStringLiteral(member.name)) {
      propertySet.add(member.name.text);
    }

    //extract class member's property, example: export class hello {info={read: {}}}
    if (isClassDeclaration(classNode) && isViewPUBasedClass(classNode)) {
      return;
    }

    if (!isPropertyDeclaration(member) || !member.initializer) {
      return;
    }

    if (isObjectLiteralExpression(member.initializer)) {
      getObjectProperties(member.initializer, propertySet);
      return;
    }

    if (isClassDeclaration(member.initializer) || isStructDeclaration(member.initializer)) {
      getClassProperties(member.initializer, propertySet);
      return;
    }

    if (isEnumDeclaration(member.initializer)) {
      getEnumProperties(member.initializer, propertySet);
      return;
    }
  });

  return;
}

export function getEnumProperties(enumNode: EnumDeclaration, propertySet: Set<string>): void {
  if (!enumNode || !enumNode.members) {
    return;
  }

  enumNode.members.forEach((member) => {
    if (!member || !member.name) {
      return;
    }

    if (isIdentifier(member.name)) {
      propertySet.add(member.name.text);
    }

    if (isStringLiteral(member.name)) {
      propertySet.add(member.name.text);
    }
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

    if (isIdentifier(propertyElement.name)) {
      propertySet.add(propertyElement.name.text);
    }

    if (isStringLiteral(propertyElement.name)) {
      propertySet.add(propertyElement.name.text);
    }

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
