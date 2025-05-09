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
import { expect } from 'chai';
import { NodeUtils, collectReservedNameForObf, hasExportModifier } from '../../../src/utils/NodeUtils';
import * as ts from 'typescript'
import sinon from 'sinon';
import { MergedConfig } from '../../../src/initialization/ConfigResolver';
import { UnobfuscationCollections } from '../../../src/utils/CommonCollections';

type Mutable<T extends object> = { -readonly [K in keyof T]: T[K] }

describe('test for NodeUtils', function () {
    describe('test for isPropertyDeclarationNode', function () {
        it('should return false if node has no parent', function () {
            const node = ts.factory.createIdentifier('name');
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.false;
        })
        it('should return ture when node.parent is PropertyAssignment', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createPropertyAssignment(node, ts.factory.createNumericLiteral('1'));
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is ComputedPropertyName', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createComputedPropertyName(node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is BindingElement', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createBindingElement(undefined, node, 'bindingElement');
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is PropertySignature', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createPropertySignature(undefined, node, undefined, ts.factory.createKeywordTypeNode(ts.SyntaxKind.StringKeyword));
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is MethodSignature', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createMethodSignature(undefined, node, undefined, undefined, [], undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is EnumMember', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createEnumMember(node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is PropertyDeclaration', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createPropertyDeclaration(undefined, undefined, node, undefined, undefined, undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is MethodDeclaration', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createMethodDeclaration(undefined, undefined, undefined, node, undefined, undefined, [], undefined, undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is SetAccessorDeclaration', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createSetAccessorDeclaration(undefined, undefined, node, [], undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
        it('should return ture when node.parent is GetAccessorDeclaration', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createGetAccessorDeclaration(undefined, undefined, node, [], undefined, undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyDeclarationNode(node)).to.be.true;
        })
    })
    describe('test for isPropertyOrElementAccessNode', function () {
        let isPropertyAccessNodeStub;
        let isElementAccessNodeStub;

        beforeEach(function () {
            isPropertyAccessNodeStub = sinon.stub(NodeUtils, 'isPropertyAccessNode').returns(false);
            isElementAccessNodeStub = sinon.stub(NodeUtils, 'isElementAccessNode').returns(false);
        });

        afterEach(function () {
            isPropertyAccessNodeStub.restore();
            isElementAccessNodeStub.restore();
        });

        it('should return true when node is a PropertyAccessNode', function () {
            const node = ts.factory.createIdentifier('name');
            isPropertyAccessNodeStub.returns(true);
            expect(NodeUtils.isPropertyOrElementAccessNode(node)).to.be.true;
        })
        it('should return true when node is a isElementAccessNode', function () {
            const node = ts.factory.createIdentifier('name');
            isElementAccessNodeStub.returns(true);
            expect(NodeUtils.isPropertyOrElementAccessNode(node)).to.be.true;
        })
        it('should return false when both isPropertyAccessNode and isElementAccessNode return false', function () {
            const node = ts.factory.createIdentifier('name');
            expect(NodeUtils.isPropertyOrElementAccessNode(node)).to.be.false;
        })
    })
    describe('test for isPropertyAccessNode', function () {
        let isInClassDeclarationStub;
        let isInExpressionStub;

        beforeEach(function () {
            isInClassDeclarationStub = sinon.stub(NodeUtils, 'isInClassDeclaration').returns(false);
            isInExpressionStub = sinon.stub(NodeUtils, 'isInExpression').returns(false);
        });

        afterEach(function () {
            isInClassDeclarationStub.restore();
            isInExpressionStub.restore();
        });

        it('should return false if node has no parent', function () {
            const node = ts.factory.createIdentifier('name');
            expect(NodeUtils.isPropertyAccessNode(node)).to.be.false;
        })
        it('should return true if isPropertyAccessExpression and parent.name equals to node', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createPropertyAccessExpression(node, node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyAccessNode(node)).to.be.true;
        })
        it('should return isInExpression(parent) if isPrivateIdentifier and isInClassDeclaration', function () {
            const node = ts.factory.createPrivateIdentifier("#name");
            const parent = ts.factory.createIdentifier('parent');
            (node as Mutable<ts.Node>).parent = parent;
            isInClassDeclarationStub.returns(true);
            isInExpressionStub.returns(true)
            expect(NodeUtils.isPropertyAccessNode(node)).to.be.true;
            isInExpressionStub.returns(false)
            expect(NodeUtils.isPropertyAccessNode(node)).to.be.false;
        })
        it('should return true if isQualifiedName and parent.right equals to node', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createQualifiedName(node, node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyAccessNode(node)).to.be.true;
        })
    })
    describe('test for isInClassDeclaration', function () {
        it('should return flase when node is undefined', function () {
            expect(NodeUtils.isInClassDeclarationForTest(undefined)).to.be.false;
        })
        it('should return true when node is ClassDeclaration', function () {
            const node = ts.factory.createClassDeclaration(undefined, undefined, undefined, undefined, undefined, []);
            expect(NodeUtils.isInClassDeclarationForTest(node)).to.be.true;
        })
        it('should return true when node is ClassExpression', function () {
            const node = ts.factory.createClassExpression(undefined, undefined, undefined, undefined, undefined, []);
            expect(NodeUtils.isInClassDeclarationForTest(node)).to.be.true;
        })
        it('should return true when node.parent is isInClassDeclaration', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createClassExpression(undefined, undefined, undefined, undefined, undefined, []);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isInClassDeclarationForTest(node)).to.be.true;
        })
    })
    describe('test for isInClassDeclaration', function () {
        it('should return flase when node is undefined', function () {
            expect(NodeUtils.isInClassDeclarationForTest(undefined)).to.be.false;
        })
        it('should return true when node is ClassDeclaration', function () {
            const node = ts.factory.createClassDeclaration(undefined, undefined, undefined, undefined, undefined, []);
            expect(NodeUtils.isInClassDeclarationForTest(node)).to.be.true;
        })
        it('should return true when node is ClassExpression', function () {
            const node = ts.factory.createClassExpression(undefined, undefined, undefined, undefined, undefined, []);
            expect(NodeUtils.isInClassDeclarationForTest(node)).to.be.true;
        })
        it('should return true when node.parent is isInClassDeclaration', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createClassExpression(undefined, undefined, undefined, undefined, undefined, []);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isInClassDeclarationForTest(node)).to.be.true;
        })
    })
    describe('test for isInExpression', function () {
        it('should return flase when node is undefined', function () {
            expect(NodeUtils.isInExpressionForTest(undefined)).to.be.false;
        })
        it('should return isInOperator(node) when node is not undefined', function () {
            let isInOperatorStub = sinon.stub(NodeUtils, 'isInOperator').returns(false);
            const node = ts.factory.createIdentifier('name');
            expect(NodeUtils.isInExpressionForTest(node)).to.be.false;
            isInOperatorStub.returns(true);
            expect(NodeUtils.isInExpressionForTest(node)).to.be.true;
            isInOperatorStub.restore();
        })
    })
    describe('test for isInOperator', function () {
        it('should return true when node is binary expression and operator is InKeyword', function () {
            const name = ts.factory.createIdentifier('name');
            const node = ts.factory.createBinaryExpression(name, ts.SyntaxKind.InKeyword, name);
            expect(NodeUtils.isInOperatorForTest(node)).to.be.true;
        })
        it('should return false when node is not binary expression', function () {
            const node = ts.factory.createIdentifier('name');
            expect(NodeUtils.isInOperatorForTest(node)).to.be.false;
        })
        it('should return false when operator is not Inkeyword', function () {
            const name = ts.factory.createIdentifier('name');
            const node = ts.factory.createBinaryExpression(name, ts.SyntaxKind.PlusEqualsToken, name);
            expect(NodeUtils.isInOperatorForTest(node)).to.be.false;
        })
    })

    describe('test for isElementAccessNode', function () {
        it('should return false if node has no parent', function () {
            const node = ts.factory.createIdentifier('name');
            expect(NodeUtils.isElementAccessNode(node)).to.be.false;
        })
        it('should return true if isElementAccessExpression and parent argumentExpression equals to node', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createElementAccessExpression(node, node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isElementAccessNode(node)).to.be.true;
        })
    })

    describe('test for isIndexedAccessNode', function () {
        it('should return false if node has no parent', function () {
            const node = ts.factory.createIdentifier('name');
            expect(NodeUtils.isIndexedAccessNode(node)).to.be.false;
        })
        it('should return false if isIndexedAccessNode but parent literalType not equals to node', function () {
            const node1 = ts.factory.createLiteralTypeNode(ts.factory.createStringLiteral("name"));
            const node2 = ts.factory.createLiteralTypeNode(ts.factory.createNumericLiteral(1));
            const parent = ts.factory.createIndexedAccessTypeNode(node2, node2);
            (node1 as Mutable<ts.Node>).parent = parent;
            (node2 as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isIndexedAccessNode(node1)).to.be.false;
            expect(NodeUtils.isIndexedAccessNode(node2)).to.be.true;
        })
        it('should return true if isIndexedAccessNode and parent literalType equals to node', function () {
            const node1 = ts.factory.createLiteralTypeNode(ts.factory.createStringLiteral("name"));
            const node2 = ts.factory.createLiteralTypeNode(ts.factory.createNumericLiteral(1));
            const parent1 = ts.factory.createIndexedAccessTypeNode(node1, node1);
            const parent2 = ts.factory.createIndexedAccessTypeNode(node2, node2);
            (node1 as Mutable<ts.Node>).parent = parent1;
            (node2 as Mutable<ts.Node>).parent = parent2;
            expect(NodeUtils.isIndexedAccessNode(node1)).to.be.true;
            expect(NodeUtils.isIndexedAccessNode(node2)).to.be.true;
        })
    })

    describe('test for isClassPropertyInConstructorParams', function () {
        it('should return false if node is not an Identifier', function () {
            const node = ts.factory.createRegularExpressionLiteral('name');
            expect(NodeUtils.isClassPropertyInConstructorParams(node)).to.be.false;
        })
        it('should return false when node has no parent', function () {
            const node = ts.factory.createIdentifier('name');
            expect(NodeUtils.isClassPropertyInConstructorParams(node)).to.be.false;
        })
        it('should return false when node parent is not a parameter', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createElementAccessExpression(node, node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isClassPropertyInConstructorParams(node)).to.be.false;
        })
        it('should return false when modifiers is undefined', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createParameterDeclaration([], undefined, node, undefined, undefined, undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isClassPropertyInConstructorParams(node)).to.be.false;
        })
        it('should return false when modifiers length is 0 or modifier is ParameterPropertyModifier', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createParameterDeclaration([ts.factory.createModifier(ts.SyntaxKind.AbstractKeyword)], undefined, node, undefined, undefined, undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isClassPropertyInConstructorParams(node)).to.be.false;
        })
        it('should return true when node parent parent is ConstructorDeclaration', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createParameterDeclaration([ts.factory.createModifier(ts.SyntaxKind.PublicKeyword)], undefined, node, undefined, undefined, undefined);
            const parentParent = ts.factory.createConstructorDeclaration(undefined, [ts.factory.createModifier(ts.SyntaxKind.AbstractKeyword)], [], undefined);
            (parent as Mutable<ts.Node>).parent = parentParent;
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isClassPropertyInConstructorParams(node)).to.be.true;
        })
    })

    describe('test for isClassPropertyInConstructorBody', function () {
        it('should return false if node is not an Identifier', function () {
            const node = ts.factory.createRegularExpressionLiteral('name');
            expect(NodeUtils.isClassPropertyInConstructorBody(node, new Set)).to.be.false;
        })
        it('shound return true when node parent is ConstructorDeclaration and constructorParams has id', function () {
            const node = ts.factory.createIdentifier('name');
            const set: Set<string> = new Set();
            set.add('name');
            const parent = ts.factory.createConstructorDeclaration(undefined, [ts.factory.createModifier(ts.SyntaxKind.AbstractKeyword)], [], undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isClassPropertyInConstructorBody(node, set)).to.be.true;
        })
        it('should return false when curNode is not a ConstructorDeclaration or id does not exist in constructorParams', function () {
            const node = ts.factory.createIdentifier('name');
            const set: Set<string> = new Set();
            set.add('test');
            const parent = ts.factory.createElementAccessExpression(node, node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isClassPropertyInConstructorBody(node, set)).to.be.false;
        })
    })

    describe('test for isPropertyNode', function () {
        it('should return true when node is PropertyOrElementAccessNode', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createElementAccessExpression(node, node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyNode(node)).to.be.true;
        })
        it('should return true when node is a PropertyDeclarationNode', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createPropertyAssignment(node, node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyNode(node)).to.be.true;
        })
        it('should return true when node is a IndexedAccessNode', function () {
            const node = ts.factory.createLiteralTypeNode(ts.factory.createStringLiteral("name"));
            const parent = ts.factory.createIndexedAccessTypeNode(node, node);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isPropertyNode(node)).to.be.true;
        })
    })

    describe('test for isObjectBindingPatternAssignment', function () {
        it('should return false when node is not VariableDeclaration', function () {
            const node = ts.factory.createObjectBindingPattern([]);
            const parent = ts.factory.createParameterDeclaration(undefined, undefined, undefined, node, undefined, undefined, undefined);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isObjectBindingPatternAssignment(node)).to.be.false;
        })
        it('should return true when node parent initializer is CallExpression', function () {
            const node = ts.factory.createObjectBindingPattern([]);
            const parent = ts.factory.createVariableDeclaration(node, undefined, undefined, undefined);
            const initializer = ts.factory.createCallExpression(ts.factory.createIdentifier('name'), undefined, undefined);
            (parent as Mutable<ts.VariableDeclaration>).initializer = initializer;
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.isObjectBindingPatternAssignment(node)).to.be.true;
        })
    })

    describe('test for isDeclarationFile', function () {
        it('should return false when sourceFile is not a declarationFile', function () {
            const endOfFileToken = ts.factory.createToken(ts.SyntaxKind.EndOfFileToken);
            const sourceFile = ts.factory.createSourceFile([], endOfFileToken, ts.NodeFlags.AwaitContext);
            expect(NodeUtils.isDeclarationFile(sourceFile)).to.be.false;
        })
    })

    describe('test for getSourceFileOfNode', function () {
        it('should return node when node kind is SyntaxKind.SourceFile', function () {
            const node = ts.factory.createIdentifier('name');
            const kind = ts.SyntaxKind.SourceFile;
            (node as Mutable<ts.Node>).kind = kind;
            expect(NodeUtils.getSourceFileOfNode(node)).to.equal(node);
        })
        it('should return node parent when node kind is not SyntaxKind.SourceFile', function () {
            const node = ts.factory.createIdentifier('name');
            const kind = ts.SyntaxKind.SymbolKeyword;
            (node as Mutable<ts.Node>).kind = kind;
            const endOfFileToken = ts.factory.createToken(ts.SyntaxKind.EndOfFileToken);
            const parent = ts.factory.createSourceFile([], endOfFileToken, ts.NodeFlags.AwaitContext);
            (node as Mutable<ts.Node>).parent = parent;
            expect(NodeUtils.getSourceFileOfNode(node)).to.equal(node.parent);
        })
    })

    describe('test for isDETSFile', function () {
        it('should return true when node fileName end with .d.ets', function () {
            const node = ts.factory.createIdentifier('name');
            const kind = ts.SyntaxKind.SourceFile;
            (node as Mutable<ts.Node>).kind = kind;
            const sourceFile = NodeUtils.getSourceFileOfNode(node);
            sourceFile.fileName = 'a.d.ets';
            expect(NodeUtils.isDETSFile(node)).to.be.true;
        })
    })

    describe('test for isNewTargetNode', function () {
        it('should return true when node parent is MetaProperty and node parent keywordToken is yntaxKind.NewKeyword and node escapedText is target', function () {
            const node = ts.factory.createIdentifier('target');
            const parent = ts.factory.createMetaProperty(ts.SyntaxKind.NewKeyword, node);
            (node as Mutable<ts.Identifier>).parent = parent;
            expect(NodeUtils.isNewTargetNode(node)).to.be.true;
        })
        it('should return false when node is not a new target node', function () {
            const node = ts.factory.createIdentifier('name');
            const parent = ts.factory.createMetaProperty(ts.SyntaxKind.ImportKeyword, node);
            (node as Mutable<ts.Identifier>).parent = parent;
            expect(NodeUtils.isNewTargetNode(node)).to.be.false;
        })
    })

    describe('test for collectReservedNameForObf', function () {
        process.env.compileTool = 'rollup';
        const ENUM_TEST1: string =
            'enum ANIMAL {\n' +
            ' CAT,\n' +
            ' DOG = CAT + 1,\n' +
            ' GOOSE = DOG + 1,\n' +
            ' DUCK = GOOSE + 1,\n' +
            '}';
        it('test1 collectReservedNameForObf-enum: -enable-property-obfuscation, shouldETSOrTSFileTransformToJS = false', function () {
            const arkConfig = new MergedConfig();
            arkConfig.options.enablePropertyObfuscation = true;
            const result: ts.TranspileOutput = ts.transpileModule(ENUM_TEST1, {
                compilerOptions: {
                    "target": ts.ScriptTarget.ES2021
                },
                fileName: "enum.ts",
                transformers: { before: [collectReservedNameForObf(arkConfig, false)] }
            });
            expect(UnobfuscationCollections.reservedEnum.has('CAT')).to.be.true;
            expect(UnobfuscationCollections.reservedEnum.has('DOG')).to.be.true;
            expect(UnobfuscationCollections.reservedEnum.has('GOOSE')).to.be.true;
            expect(UnobfuscationCollections.reservedEnum.has('DUCK')).to.be.false;
            UnobfuscationCollections.clear();
        })

        const ENUM_TEST2: string =
            'let test = 1;\n' +
            'enum ANIMAL {\n' +
            ' CAT,\n' +
            ' DOG = (CAT + 1) + test,\n' +
            '}';
        it('test2 collectReservedNameForObf-enum: -enable-property-obfuscation, shouldETSOrTSFileTransformToJS = false', function () {
            const arkConfig = new MergedConfig();
            arkConfig.options.enablePropertyObfuscation = true;
            const result: ts.TranspileOutput = ts.transpileModule(ENUM_TEST2, {
                compilerOptions: {
                    "target": ts.ScriptTarget.ES2021
                },
                fileName: "enum.ts",
                transformers: { before: [collectReservedNameForObf(arkConfig, false)] }
            });
            expect(UnobfuscationCollections.reservedEnum.has('CAT')).to.be.true;
            expect(UnobfuscationCollections.reservedEnum.has('test')).to.be.true;
            expect(UnobfuscationCollections.reservedEnum.has('DOG')).to.be.false;
            UnobfuscationCollections.clear();
        })

        const ENUM_TEST3: string =
            'class TEST{\n' +
            ' prop1 = 1\n' +
            '}\n' +
            'let myclass = new TEST();\n' +
            'enum TEST1{\n' +
            ' AAA,\n' +
            ' BBB = AAA + myclass.prop1\n' +
            '}';
        it('test3 collectReservedNameForObf-enum: -enable-property-obfuscation, shouldETSOrTSFileTransformToJS = false', function () {
            const arkConfig = new MergedConfig();
            arkConfig.options.enablePropertyObfuscation = true;
            const result: ts.TranspileOutput = ts.transpileModule(ENUM_TEST3, {
                compilerOptions: {
                    "target": ts.ScriptTarget.ES2021
                },
                fileName: "enum.ts",
                transformers: { before: [collectReservedNameForObf(arkConfig, false)] }
            });
            expect(UnobfuscationCollections.reservedEnum.has('AAA')).to.be.true;
            expect(UnobfuscationCollections.reservedEnum.has('myclass')).to.be.true;
            expect(UnobfuscationCollections.reservedEnum.has('BBB')).to.be.false;
            expect(UnobfuscationCollections.reservedEnum.has('prop1')).to.be.false;
            UnobfuscationCollections.clear();
        })

        it('test4 collectReservedNameForObf-enum: -enable-property-obfuscation, shouldETSOrTSFileTransformToJS = true', function () {
            const arkConfig = new MergedConfig();
            arkConfig.options.enablePropertyObfuscation = true;
            const result: ts.TranspileOutput = ts.transpileModule(ENUM_TEST3, {
                compilerOptions: {
                    "target": ts.ScriptTarget.ES2021
                },
                fileName: "enum.js",
                transformers: { before: [collectReservedNameForObf(arkConfig, true)] }
            });
            expect(UnobfuscationCollections.reservedEnum.size === 0).to.be.true;
            UnobfuscationCollections.clear();
        })

        const STRUCT_TEST1: string =
            'class ViewPU {}\n' +
            'export class Retransmission1 extends ViewPU {\n' +
            ' constructor() {\n' +
            '  super();\n' +
            ' }\n' +
            ' scroller1: string;\n' +
            ' controller1: number;\n' +
            ' callMethod1(): void {};\n' +
            '}\n' +
            'class Retransmission2 extends ViewPU {\n' +
            ' constructor() {\n' +
            '  super();\n' +
            ' }\n' +
            ' scroller2: string;\n' +
            ' controller2: number;\n' +
            ' callMethod2(): void {};\n' +
            '}';
        it('test5 collectReservedNameForObf-struct: -enable-property-obfuscation, shouldETSOrTSFileTransformToJS = false', function () {
            const arkConfig = new MergedConfig();
            arkConfig.options.enablePropertyObfuscation = true;
            const result: ts.TranspileOutput = ts.transpileModule(STRUCT_TEST1, {
                compilerOptions: {
                    "target": ts.ScriptTarget.ES2021
                },
                fileName: "enum.ts",
                transformers: { before: [collectReservedNameForObf(arkConfig, false)] }
            });
            expect(UnobfuscationCollections.reservedStruct.has('scroller1')).to.be.true;
            expect(UnobfuscationCollections.reservedStruct.has('controller1')).to.be.true;
            expect(UnobfuscationCollections.reservedStruct.has('callMethod1')).to.be.true;
            expect(UnobfuscationCollections.reservedStruct.has('scroller2')).to.be.true;
            expect(UnobfuscationCollections.reservedStruct.has('controller2')).to.be.true;
            expect(UnobfuscationCollections.reservedStruct.has('callMethod2')).to.be.true;
            UnobfuscationCollections.clear();
        })

        it('test6 collectReservedNameForObf-struct: -disable-obfuscation', function () {
            const arkConfig = new MergedConfig();
            arkConfig.options.disableObfuscation = true;
            arkConfig.options.enablePropertyObfuscation = true;
            const result: ts.TranspileOutput = ts.transpileModule(STRUCT_TEST1, {
                compilerOptions: {
                    "target": ts.ScriptTarget.ES2021
                },
                fileName: "enum.ts",
                transformers: { before: [collectReservedNameForObf(arkConfig, false)] }
            });
            expect(UnobfuscationCollections.reservedStruct.size === 0).to.be.true;
            UnobfuscationCollections.clear();
        })
    })

  describe('test for hasExportModifier', function () {
    it('should return false if has no modifier', function () {
      const fileContent = `
      let a = 1;
    `;
      const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
      expect(hasExportModifier(sourceFile.statements[0])).to.be.false;
    })
    it('should return false if has no export modifier', function () {
      const fileContent = `
      declare const a = 1;
    `;
      const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
      expect(hasExportModifier(sourceFile.statements[0])).to.be.false;
    })
    it('should return true if has export modifier', function () {
      const fileContent = `
      export const a = 1;
    `;
      const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
      expect(hasExportModifier(sourceFile.statements[0])).to.be.true;
    })
  })

  describe('test for isObjectLiteralInAnnotation', function () {
    it('should return false when node is not ObjectLiteral', function () {
        const node = ts.factory.createObjectBindingPattern([]);
        expect(NodeUtils.isObjectLiteralInAnnotation(node, '.d.ets')).to.be.false;
    })
    it('should return true if annotation is in .d.ets files', function () {
        const node = ts.factory.createObjectLiteralExpression(
            [ts.factory.createPropertyAssignment(
              ts.factory.createIdentifier("a"),
              ts.factory.createNumericLiteral("1")
            )],
            false
        );
        const expr = ts.factory.createCallExpression(
            ts.factory.createIdentifier("Anno1"),
            undefined,
            [node]
        );
        (node as Mutable<ts.Node>).parent = expr;
        const decorator = ts.factory.createDecorator(expr);
        (expr as Mutable<ts.Node>).parent = decorator;
        expect(NodeUtils.isObjectLiteralInAnnotation(node, '.d.ets')).to.be.true;
    })
    it('should return true if annotation is in .ts files and with annotationPrefix', function () {
        const node = ts.factory.createObjectLiteralExpression(
            [ts.factory.createPropertyAssignment(
              ts.factory.createIdentifier("a"),
              ts.factory.createNumericLiteral("1")
            )],
            false
        );
        const expr = ts.factory.createCallExpression(
            ts.factory.createIdentifier("__$$ETS_ANNOTATION$$__Anno1"),
            undefined,
            [node]
        );
        (node as Mutable<ts.Node>).parent = expr;
        const decorator = ts.factory.createDecorator(expr);
        (expr as Mutable<ts.Node>).parent = decorator;
        expect(NodeUtils.isObjectLiteralInAnnotation(node, '.ts')).to.be.true;
    })
})
})