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

import {
  isViewPUBasedClass,
  getElementAccessExpressionProperties,
  stringPropsSet,
  structPropsSet,
  getTypeAliasProperties,
  getInterfaceProperties,
  getClassProperties,
  getEnumProperties,
  getObjectProperties
} from '../../../src/utils/OhsUtil';
import { describe, it } from 'mocha';
import { expect } from 'chai';
import * as ts from 'typescript';

describe('unit test for OhsUtil.ts', function () {
  describe('test for isViewPUBasedClass function', function () {
    it('should return false if classNode is an empty object', () => {
      const classNode = {} as any;
      expect(isViewPUBasedClass(classNode)).to.be.false;
    });

    it('should return false if heritageClauses is undefined', () => {
      const classNode = ts.factory.createClassDeclaration(undefined, "Class", undefined, undefined, []);
      expect(isViewPUBasedClass(classNode)).to.be.false;
    });

    it('should return false if classNode is undefined', () => {
      expect(isViewPUBasedClass(undefined)).to.be.false;
    });

    it('should return false if heritageClause.types is undefined', () => {
      const heritageClause = ts.factory.createHeritageClause(ts.SyntaxKind.ExtendsKeyword, undefined);
      const classNode = ts.factory.createClassDeclaration(undefined, "Class", undefined, [heritageClause], []);
      expect(isViewPUBasedClass(classNode)).to.be.false;
    });

    it('should return false if classNode.heritageClause.types.member is undefined', () => {
      const heritageClause = ts.factory.createHeritageClause(ts.SyntaxKind.ExtendsKeyword, [undefined]);
      const classNode = ts.factory.createClassDeclaration(undefined, "Class", undefined, [heritageClause], []);
      expect(isViewPUBasedClass(classNode)).to.be.false;
    })

    it('should return true if classNode is set', () => {
      const typeArguments = [
        ts.factory.createKeywordTypeNode(ts.SyntaxKind.NumberKeyword),
      ];
      const type = ts.factory.createExpressionWithTypeArguments(ts.factory.createIdentifier('ViewPU'), typeArguments);
      const heritageClause = ts.factory.createHeritageClause(ts.SyntaxKind.ExtendsKeyword, [type]);
      const classNode = ts.factory.createClassDeclaration(undefined, "Class", undefined, [heritageClause], []);
      expect(isViewPUBasedClass(classNode)).to.be.true;
    });
  })

  describe('test for getTypeAliasProperties function', function () {
    it('should not add items to propertySet if type is undefined', () => {
      const name = ts.factory.createIdentifier('MyType');
      const typeAliasNode = ts.factory.createTypeAliasDeclaration(undefined, name, undefined, undefined);
      const propertySet = new Set<string>();
      getTypeAliasProperties(typeAliasNode, propertySet);
      expect(stringPropsSet.size == 0).to.be.true;
    });

    it('should add to propertySet if member.name is set', () => {
      const name = ts.factory.createIdentifier('MyType');
      const type = ts.factory.createKeywordTypeNode(ts.SyntaxKind.StringKeyword);
      const identifierName = ts.factory.createIdentifier('Identifier');
      const stringName = ts.factory.createStringLiteral('String');
      const computedPropertyName = ts.factory.createComputedPropertyName(ts.factory.createStringLiteral('3 + 2'));
      const types = ts.factory.createTypeLiteralNode([
        ts.factory.createPropertySignature(undefined, undefined, undefined, type),
        ts.factory.createPropertySignature(undefined, identifierName, undefined, type),
        ts.factory.createPropertySignature(undefined, stringName, undefined, type),
        ts.factory.createPropertySignature(undefined, computedPropertyName, undefined, type),
      ]);
      const typeAliasNode = ts.factory.createTypeAliasDeclaration(undefined, name, undefined, types);
      const propertySet = new Set<string>();
      getTypeAliasProperties(typeAliasNode, propertySet);
      expect(propertySet.has('Identifier') && propertySet.has('String') && propertySet.has('3 + 2')).to.be.true;
      expect(stringPropsSet.has('String') && propertySet.has('3 + 2')).to.be.true;
    });
  })

  describe('test for getElementAccessExpressionProperties function', function () {
    it('should not add items to propertySet if elementAccessExpression is undefined', () => {
      const propertySet = new Set<string>();
      getElementAccessExpressionProperties(undefined, propertySet);
      expect(stringPropsSet.has('value')).to.be.false;
    });

    it('should add to propertySet if elementAccessExpressionNode.argumentExpression is set string value', () => {
      const key = ts.factory.createStringLiteral('key');
      const value = ts.factory.createStringLiteral('value');
      const elementAccessExpression = ts.factory.createElementAccessExpression(key, value);
      const propertySet = new Set<string>();
      getElementAccessExpressionProperties(elementAccessExpression, propertySet);
      expect(stringPropsSet.has('value')).to.be.true;
    });

    it('should not add items to propertySet if elementAccessExpressionNode.argumentExpression is set int value', () => {
      const key = ts.factory.createIdentifier('key');
      const value = ts.factory.createBigIntLiteral("9999999");
      const elementAccessExpression = ts.factory.createElementAccessExpression(key, value);
      const propertySet = new Set<string>();
      getElementAccessExpressionProperties(elementAccessExpression, propertySet)
      expect(stringPropsSet.has('9999999')).to.be.false;
    });
  })

  describe('test for getInterfaceProperties function', function () {
    it('should not add items to propertySet if interfaceNode is undefined', () => {
      const propertySet = new Set<string>();
      getInterfaceProperties(undefined, propertySet);
      expect(stringPropsSet.has('property')).to.be.false;
    });

    it('should add to propertySet if member.name is set string value', () => {
      const members = [
        ts.factory.createPropertySignature([], undefined, undefined, undefined),
        ts.factory.createPropertySignature([], ts.factory.createStringLiteral('property'), undefined, undefined)
      ];
      const interfaceNode = ts.factory.createInterfaceDeclaration(undefined, 'Interface', undefined, undefined, members);
      const propertySet = new Set<string>();
      getInterfaceProperties(interfaceNode, propertySet);
      expect(stringPropsSet.has('property')).to.be.true;
      expect(propertySet.has('property')).to.be.true;
    });
  })

  describe('test for getClassProperties function', function () {
    it('should not add items to propertySet if classNode is undefined', () => {
      const propertySet = new Set<string>();
      getClassProperties(undefined, propertySet);
      expect(propertySet.size == 0).to.be.true;
    });

    it('should add to propertySet if classNode is StructDeclaration', () => {
      const classProperty = ts.factory.createClassExpression(
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        []
      );
      const parameters = [
        ts.factory.createParameterDeclaration(
          [ts.factory.createModifier(ts.SyntaxKind.AbstractKeyword)],
          undefined,
          'parameter',
          undefined,
          ts.factory.createKeywordTypeNode(ts.SyntaxKind.NumberKeyword),
          undefined
        ),
        ts.factory.createParameterDeclaration(
          [ts.factory.createModifier(ts.SyntaxKind.PublicKeyword)],
          undefined,
          'classParameter',
          undefined,
          ts.factory.createKeywordTypeNode(ts.SyntaxKind.NumberKeyword),
          classProperty
        )
      ];
      const expression = ts.factory.createBinaryExpression(
        ts.factory.createIdentifier('left'),
        ts.SyntaxKind.EqualsToken,
        ts.factory.createIdentifier('right')
      );
      const statements = [ts.factory.createExpressionStatement(expression)];
      const members = [
        undefined,
        ts.factory.createPropertyDeclaration(undefined, 'name', undefined, undefined, undefined),
        ts.factory.createConstructorDeclaration(
          undefined,
          undefined,
          parameters,
          ts.factory.createBlock(statements, true)
        )
      ];
      const structDeclaration = ts.factory.createStructDeclaration(undefined, undefined, undefined, undefined, members);
      const propertySet = new Set<string>();
      getClassProperties(structDeclaration, propertySet);
      expect(structPropsSet.has('name')).to.be.true;
      expect(propertySet.has('parameter')).to.be.false;
      expect(propertySet.has('classParameter')).to.be.true;
    });

    describe('test for getEnumProperties function', function () {
      it('should not add items to propertySet if enumNode is undefined', () => {
        const propertySet = new Set<string>();
        getEnumProperties(undefined, propertySet);
        expect(propertySet.size === 0).to.be.true;
      });

      it('should add to propertySet if member.name is set', () => {
        const members = [
          undefined,
          ts.factory.createEnumMember('enumMember', ts.factory.createIdentifier('enumMember')),
        ];
        const enumNode = ts.factory.createEnumDeclaration(undefined, undefined, 'enum', members);
        const propertySet = new Set<string>();
        getEnumProperties(enumNode, propertySet);
        expect(propertySet.has('enumMember')).to.be.true;
      });
    })

    describe('test for getObjectProperties function', function () {
      it('should not add items to propertySet if objNode is undefined', () => {
        const propertySet = new Set<string>();
        getObjectProperties(undefined, propertySet);
        expect(propertySet.size === 0).to.be.true;
      });

      it('should add to propertySet if property.name is set', () => {
        const objProperties = [
          ts.factory.createPropertyAssignment('objKey', ts.factory.createStringLiteral('objValue'))
        ];
        const obj = ts.factory.createObjectLiteralExpression(objProperties);
        const properties = [
          undefined,
          ts.factory.createPropertyAssignment('key', obj),
          ts.factory.createShorthandPropertyAssignment('key2', obj)
        ];
        const objNode = ts.factory.createObjectLiteralExpression(properties, true);
        const propertySet = new Set<string>();
        getObjectProperties(objNode, propertySet);
        expect(propertySet.has('key')).to.be.true;
        expect(propertySet.has('objKey')).to.be.true;
      });
    })
  })
}); 
