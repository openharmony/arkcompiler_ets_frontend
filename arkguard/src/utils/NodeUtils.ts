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
  createPrinter,
  EmitHint,
  factory,
  forEachChild,
  isBinaryExpression,
  isBindingElement,
  isCallExpression,
  isComputedPropertyName,
  isConstructorDeclaration,
  isElementAccessExpression,
  isEnumMember,
  isExpressionStatement,
  isForInStatement,
  isForOfStatement,
  isForStatement,
  isGetAccessor,
  isIdentifier,
  isMethodDeclaration,
  isMethodSignature,
  isParameter,
  isPropertyAccessExpression,
  isPropertyAssignment,
  isPropertyDeclaration,
  isPropertySignature, isQualifiedName,
  isSetAccessor,
  isStringLiteral,
  isTaggedTemplateExpression, isVariableDeclaration,
  isWhileStatement,
  NodeFlags,
  SyntaxKind
} from 'typescript';

import type {
  BinaryExpression,
  Block,
  ElementAccessExpression,
  Expression,
  Node,
  NodeArray,
  ObjectBindingPattern,
  Printer,
  PrinterOptions,
  PropertyAccessExpression,
  SourceFile,
  Statement,
  StringLiteralLike,
  VariableDeclaration,
  VariableStatement 
} from 'typescript';

import * as crypto from 'crypto';

export class NodeUtils {
  public static setSynthesis<T extends Node>(node: T): T {
    visit(node);
    return node;

    function visit(node: Node): void {
      if (node) {
        (node.pos as number) = -1;
        (node.end as number) = -1;
        forEachChild(node, visit);
      }
    }
  }

  public static isPropertyDeclarationNode(node: Node): boolean {
    let parent: Node | undefined = node.parent;
    if (!parent) {
      return false;
    }

    /** eg: { 'name'' : 'akira' }, pass */
    if (isPropertyAssignment(parent)) {
      return parent.name === node;
    }

    if (isComputedPropertyName(parent) && parent.expression === node) {
      return true;
    }

    /** object binding pattern */
    if (isBindingElement(parent) && parent.propertyName === node) {
      return true;
    }

    /** eg: interface/type inf { 'name' : string}, pass */
    if (isPropertySignature(parent) && parent.name === node) {
      return true;
    }

    /** eg: interface/type T1 { func(arg: string): number;} */
    if (isMethodSignature(parent) && parent.name === node) {
      return true;
    }

    /** eg: enum { xxx = 1}; */
    if (isEnumMember(parent) && parent.name === node) {
      return true;
    }

    /** class { private name= 1}; */
    if (isPropertyDeclaration(parent) && parent.name === node) {
      return true;
    }

    /** class {'getName': function() {}} let _ = { getName() [}} */
    if (isMethodDeclaration(parent) && parent.name === node) {
      return true;
    }

    if (isSetAccessor(parent) && parent.name === node) {
      return true;
    }

    const result: boolean = isGetAccessor(parent) && parent.name === node;
    return result;
  }

  public static isPropertyOrElementAccessNode(node: Node): boolean {
    return this.isPropertyAccessNode(node) || this.isElementAccessNode(node) || false;
  }

  public static isPropertyAccessNode(node: Node): boolean {
    let parent: Node | undefined = node.parent;
    if (!parent) {
      return false;
    }

    /** eg: a.b = 1 */
    if (isPropertyAccessExpression(parent) && parent.name === node) {
      return true;
    }
    const result: boolean = isQualifiedName(parent) && parent.right === node;
    return result;
  }

  public static isElementAccessNode(node: Node): boolean {
    let parent: Node | undefined = node.parent;
    if (!parent) {
      return false;
    }

    /** eg: a['name'] = 1, pass, a[0] ignore */
    const result: boolean = isElementAccessExpression(parent) && parent.argumentExpression === node;
    return result;
  }

  public static isClassPropertyInConstructorParams(node: Node): boolean {
    if (!isIdentifier(node)) {
      return false;
    }

    if (!node.parent || !isParameter(node.parent)) {
      return false;
    }

    return !(!node.parent.parent || !isConstructorDeclaration(node.parent.parent));
  }

  public static isClassPropertyInConstructorBody(node: Node, constructorParams: Set<string>): boolean {
    if (!isIdentifier(node)) {
      return false;
    }

    const id: string = node.escapedText.toString();
    let curNode: Node = node.parent;
    while (curNode) {
      if (isConstructorDeclaration(curNode) && constructorParams.has(id)) {
        return true;
      }

      curNode = curNode.parent;
    }

    return false;
  }

  public static isPropertyNode(node: Node): boolean {
    if (this.isPropertyOrElementAccessNode(node)) {
      return true;
    }

    return this.isPropertyDeclarationNode(node);
  }

  /**
   * let b = {
   *      'id' : 'id22'
   *  }
   *       let c = ['123']
   *       interface tmp1 {
   *      ['id'] : string;    // pass
   *      // [b.id] : string;    // error
   *      [b['id']]() : string;  // error
   *  };
   *
   *       enum tmp2{
   *      ['id'] = 2, // pass
   *      [b.id] = 3, // error
   *  };
   *
   *
   *       let _ = {
   *      ['id'] : 2, // pass,
   *      [b.id] : 3, // pass,
   *  }
   *
   *  interface IPerson {
   *     'jfkkf': number,
   *     ['kkk'] : number
   * }
   *
   * var customer:IPerson = {
   *     'jfkkf': 10,
   *     ['kkk']: 11
   * }
   *
   *       class A {
   *
   *      private ['id'] = 2; // pass
   *      private [b.id] = 2; // error
   *  }
   *
   *       class B {
   *      ['id']() {}
   *      [c[0]]() {
   *      }
   *  }
   *
   *1. The computable method declaration string of the class can be converted into an array access form;
   *2. Computable properties/methods of object literals, which can be converted into array access forms;
   *3. Cannot convert to array access form in other forms
   * Interface/Type:  A computed property name in an interface must refer to an expression whose type is a literal type or a 'unique symbol' type.
   * Enum Computed property names are not allowed in enums.
   * ClassDefinition A computed property name in a class property declaration must refer to an expression whose type is a literal type or a 'unique symbol' type.
   * @param node
   */
  public static isExtractableString(node: StringLiteralLike): boolean {
    let parent: Node | undefined = node.parent;
    if (!parent) {
      return false;
    }

    if (isTaggedTemplateExpression(parent)) {
      return false;
    }

    if (!NodeUtils.isPropertyDeclarationNode(node)) {
      return true;
    }

    // skip for some situations when in property declaration.
    /** let _ = { ['name']: 'jack'} => let _ = {[arr[0]]: 'jack'} */
    if (isComputedPropertyName(parent)) {
      let grandparent: Node = parent.parent;
      const result: boolean = isMethodDeclaration(grandparent) && grandparent.name === parent;
      return result;
    }

    return false;
  }

  public static randomInsertStatements(statements: Statement[], newStatement: Statement): Statement[] {
    let index: number = crypto.randomInt(0, statements.length);
    const result: Statement[] = [...statements.slice(0, index), newStatement, ...statements.slice(index, statements.length)];
    return result;
  }

  /**
   * create array init statement, e.g.:
   * const arr = [1,2,3,4];
   * only support string and numeric array
   */
  public static createArrayInit(isConst: boolean, varName: string, valueType: SyntaxKind, initArray: string[]): VariableStatement {
    let idArr: Expression[] = [];
    for (const value of initArray) {
      if (valueType === SyntaxKind.StringLiteral) {
        idArr.push(factory.createStringLiteral(value));
      }

      if (valueType === SyntaxKind.NumericLiteral) {
        idArr.push(factory.createNumericLiteral(value));
      }
    }

    const declaration: VariableDeclaration = factory.createVariableDeclaration(
      factory.createIdentifier(varName),
      undefined,
      undefined,
      factory.createArrayLiteralExpression(idArr, false)
    );

    return factory.createVariableStatement(
      undefined,
      factory.createVariableDeclarationList([declaration], NodeFlags.Const)
    );
  }

  /**
   * create numeric variable declaration with random value
   * const varName = Math.floor(Math.random() * (max - min) + min);
   * @return integer random value in range [min, max]
   */
  public static createNumericWithRandom(varName: string, min: number, max: number): VariableStatement {
    let innerBinary: BinaryExpression = factory.createBinaryExpression(
      factory.createCallExpression(
        factory.createPropertyAccessExpression(
          factory.createIdentifier('Math'),
          factory.createIdentifier('random')
        ),
        undefined,
        []
      ),
      SyntaxKind.AsteriskToken,
      factory.createNumericLiteral(max - min)
    );

    if (min !== 0) {
      innerBinary = factory.createBinaryExpression(
        innerBinary,
        SyntaxKind.PlusToken,
        factory.createNumericLiteral(min)
      );
    }

    const declaration: VariableDeclaration = factory.createVariableDeclaration(
      factory.createIdentifier(varName),
      undefined,
      undefined,
      factory.createCallExpression(
        factory.createPropertyAccessExpression(
          factory.createIdentifier('Math'),
          factory.createIdentifier('floor')
        ),
        undefined,
        [
          innerBinary
        ]
      )
    );

    return factory.createVariableStatement(
      null,
      factory.createVariableDeclarationList([declaration], NodeFlags.Const)
    );
  }

  /**
   * create variable lower expression: (x | 0)
   * @private
   */
  public static createLowerExpression(expression: Expression): Expression {
    return factory.createParenthesizedExpression(
      factory.createBinaryExpression(
        {...expression},
        SyntaxKind.BarToken,
        factory.createNumericLiteral('0')
      )
    );
  }

  /**
   * create trunc expression: Math.trunc(x)
   */
  public static createTruncExpression(expression: Expression): Expression {
    return factory.createCallExpression(
      factory.createPropertyAccessExpression(
        factory.createIdentifier('Math'),
        factory.createIdentifier('trunc')
      ),
      undefined,
      [
        {...expression}
      ]
    );
  }

  /**
   * change property access expression to element access expression
   * example:
   *      console.log() -> console['log']()
   */
  public static changePropertyAccessToElementAccess(expression: PropertyAccessExpression): ElementAccessExpression {
    return factory.createElementAccessExpression(
      {...expression.expression},
      factory.createStringLiteral(expression.name.escapedText.toString())
    );
  }

  public static isMostInnerBinary(node: Node): boolean {
    let flag: boolean = true;
    forEachChild(node, (child) => {
      if (!flag) {
        return;
      }

      if (this.hasBinary(child)) {
        flag = false;
        return;
      }
    });

    return flag;
  }

  private static hasBinary(node: Node): boolean {
    let flag: boolean = false;
    let visit = (inputNode): void => {
      if (flag) {
        return;
      }

      if (isBinaryExpression(inputNode)) {
        flag = true;
        return;
      }

      forEachChild(inputNode, visit);
    };

    visit(node);
    return flag;
  }

  public static isMostInnerCallExpression(node: Node): boolean {
    let flag: boolean = true;
    forEachChild(node, (child) => {
      if (!flag) {
        return;
      }

      if (this.hasCallExpression(child)) {
        flag = false;
        return;
      }
    });

    return flag;
  }

  private static hasCallExpression(node: Node): boolean {
    let flag: boolean = false;
    let visit = (inputNode): void => {
      if (flag) {
        return;
      }

      if (isCallExpression(inputNode)) {
        flag = true;
        return;
      }

      forEachChild(inputNode, visit);
    };

    visit(node);
    return flag;
  }

  public static isContainNarrowNames(node: Node, narrowNames: string[]): boolean {
    let flag: boolean = false;
    forEachChild(node, (child) => {
      if (flag) {
        return;
      }

      if (this.hasNarrowNames(child, narrowNames)) {
        flag = true;
        return;
      }
    });

    return flag;
  }

  private static hasNarrowNames(node: Node, narrowNames: string[]): boolean {
    let flag: boolean = false;
    let visit = (inputNode: Node): void => {
      if (flag) {
        return;
      }

      if (isIdentifier(inputNode) &&
        narrowNames.includes(inputNode.text)) {
        flag = true;
        return;
      }

      if (isStringLiteral(inputNode) &&
        narrowNames.includes(inputNode.text)) {
        flag = true;
        return;
      }

      forEachChild(inputNode, visit);
    };

    visit(node);
    return flag;
  }

  public static isContainForbidStringStatement(node: Block): boolean {
    let result: boolean = false;
    let statements: NodeArray<Statement> = node.statements;

    statements?.forEach((st: Statement) => {
      if (isExpressionStatement(st) && isStringLiteral(st.expression)) {
        result = true;
      }
    });

    return result;
  }

  public static printNode(node: Node, sourceFile: SourceFile): string {
    const printOptions: PrinterOptions = {};
    const printer: Printer = createPrinter(printOptions);

    return printer.printNode(EmitHint.Unspecified, node, sourceFile);
  }

  public static isLoopStatement(node: Node): boolean {
    return isForStatement(node) ||
      isForInStatement(node) ||
      isForOfStatement(node) ||
      isWhileStatement(node);
  }

  public static isObjectBindingPatternAssignment(node: ObjectBindingPattern): boolean {
    if (!node || !node.parent || !isVariableDeclaration(node.parent)) {
      return false;
    }

    const initializer: Expression = node.parent.initializer;
    return initializer && isCallExpression(initializer);
  }
}
