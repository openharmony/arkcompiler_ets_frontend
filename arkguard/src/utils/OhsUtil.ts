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
  getModifiers,
  isGetAccessor,
  isSetAccessor,
  isShorthandPropertyAssignment,
  isSpreadAssignment,
  isMethodDeclaration,
  isGetAccessorDeclaration,
  isAccessor,
} from 'typescript';

import type {
  ClassDeclaration,
  ClassExpression,
  ElementAccessExpression,
  EnumDeclaration,
  Expression,
  GetAccessorDeclaration,
  HeritageClause,
  Identifier,
  InterfaceDeclaration,
  MethodDeclaration,
  Modifier,
  NodeArray,
  ObjectLiteralExpression,
  PropertyAssignment,
  PropertyName,
  SetAccessorDeclaration,
  ShorthandPropertyAssignment,
  Statement,
  StructDeclaration,
  TypeAliasDeclaration,
} from 'typescript';

import { ApiExtractor } from '../common/ApiExtractor';
import { UnobfuscationCollections } from './CommonCollections';

export const stringPropsSet: Set<string> = new Set();
/**
 * The struct properties may be initialized in other files, but the properties in the struct definition are not obfuscated.
 * So the whitelist of struct properties is collected during the project scanning process.
 */
export const structPropsSet: Set<string> = new Set();

/**
 * Add enum elements into whitelist when compiling har module to avoid obfuscating enum elements
 * since enum elements in js file cannot be obfuscated properly.
 */
export const enumPropsSet: Set<string> = new Set();

/**
 * Collect the original name of export elements to ensure we can collect their properties
 */
export const exportOriginalNameSet: Set<string> = new Set();

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
export function isViewPUBasedClass(classNode: ClassDeclaration | undefined): boolean {
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

export function isParameterPropertyModifier(modifier: Modifier): boolean {
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

  if (isStructDeclaration(classNode)) {
    getStructProperties(classNode, structPropsSet);
  }
  traverseMembersOfClass(classNode, propertySet);
  return;
}

function traverseMembersOfClass(classNode: ClassDeclaration | ClassExpression | StructDeclaration, propertySet: Set<string>): void {
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
        const modifiers = getModifiers(parameter);
        if (isParameter(parameter) && modifiers && modifiers.length > 0) {
          if (parameter.name && isIdentifier(parameter.name)) {
            let hasParameterPropertyModifier = modifiers.find(modifier => isParameterPropertyModifier(modifier)) !== undefined;
            if (hasParameterPropertyModifier) {
              propertySet.add(parameter.name.text);
              ApiExtractor.mConstructorPropertySet?.add(parameter.name.text);
            }
          }
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

export function getStructProperties(structNode: StructDeclaration, propertySet: Set<string>): void {
  structNode?.members?.forEach((member) => {
    const memberName: PropertyName = member?.name;
    if (!memberName) {
      return;
    }
    collectPropertyNamesAndStrings(memberName, propertySet);
  });
}

/**
 * collect elements into export whitelist for module.exports = {A, B, C, D}
 * since these elements can be import by `const {A, B, C, D} = require("./filePath");`
 */
export function getObjectExportNames(objNode: ObjectLiteralExpression, exportNames: Set<string>): void {
  if (!objNode || !objNode.properties) {
    return;
  }

  objNode.properties.forEach((propertyElement) => {
    if (isPropertyAssignment(propertyElement)) {
      /**
       * { prop1: 123 } // collect prop1
       * { 'prop2': 123 } // collect prop2
       * { ['prop3']: 123 } // collect prop3
       */
      addExportPropertyName(propertyElement, exportNames);

      let initializer = propertyElement.initializer;
      if (isIdentifier(initializer)) {
        /**
         * { prop: testObj } // collect testObj into exportOriginalNameSet so that its properties can be collected
         */
        exportOriginalNameSet.add(initializer.text);
      }
      return;
    }

    if (isShorthandPropertyAssignment(propertyElement)) {
      /**
       * let shorthandNode = {prop1: 123};
       * module.exports = { shorthandNode } // collect shorthandNode
       */
      exportNames.add(propertyElement.name.text);
      return;
    }

    if (isMethodDeclaration(propertyElement) || isGetAccessor(propertyElement) || isSetAccessor(propertyElement)) {
      /**
       * { method() {} } // collect method
       * { 'method'() {} } // collect method
       * { ['method']() {} } // collect method
       * { get getProp() {} } // collect getProp
       * { get 'getProp'() {} } // collect getProp
       * { get ['getProp']() {}} // collect getProp
       */
      addExportPropertyName(propertyElement, exportNames);
      return;
    }
  });

  return;
}

/**
 * Collect property names in ObjectLiteralExpression
 */
export function addExportPropertyName(propertyElement: PropertyAssignment | MethodDeclaration |
   GetAccessorDeclaration | SetAccessorDeclaration, exportNames: Set<string>): void {
    let nameNode = propertyElement.name;

    if (isIdentifier(nameNode) || isStringLiteral(nameNode)) {
      exportNames.add(nameNode.text);
    }

    if (isComputedPropertyName(nameNode) && isStringLiteral(nameNode.expression)) {
      exportNames.add(nameNode.expression.text);
    }
}