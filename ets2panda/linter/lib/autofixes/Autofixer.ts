/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
import { TsUtils } from '../utils/TsUtils';
import { FaultID } from '../Problems';
import { scopeContainsThis } from '../utils/functions/ContainsThis';
import { forEachNodeInSubtree } from '../utils/functions/ForEachNodeInSubtree';
import { NameGenerator } from '../utils/functions/NameGenerator';
import { isAssignmentOperator } from '../utils/functions/isAssignmentOperator';
import { SymbolCache } from './SymbolCache';

const GENERATED_OBJECT_LITERAL_INTERFACE_NAME = 'GeneratedObjectLiteralInterface_';
const GENERATED_OBJECT_LITERAL_INTERFACE_TRESHOLD = 1000;

const GENERATED_TYPE_LITERAL_INTERFACE_NAME = 'GeneratedTypeLiteralInterface_';
const GENERATED_TYPE_LITERAL_INTERFACE_TRESHOLD = 1000;

const GENERATED_DESTRUCT_OBJECT_NAME = 'GeneratedDestructObj_';
const GENERATED_DESTRUCT_OBJECT_TRESHOLD = 1000;

const GENERATED_DESTRUCT_ARRAY_NAME = 'GeneratedDestructArray_';
const GENERATED_DESTRUCT_ARRAY_TRESHOLD = 1000;

export interface Autofix {
  replacementText: string;
  start: number;
  end: number;
}

export class Autofixer {
  constructor(
    private readonly typeChecker: ts.TypeChecker,
    private readonly utils: TsUtils,
    readonly sourceFile: ts.SourceFile,
    readonly cancellationToken?: ts.CancellationToken
  ) {
    this.symbolCache = new SymbolCache(this.typeChecker, this.utils, sourceFile, cancellationToken);
  }

  /**
   * Generates the text representation for destructuring elements in an object.
   * @param variableDeclarationMap - Map of property names to variable names.
   * @param newObjectName - Name of the new object to destructure.
   * @param declarationFlags - Flags for the variable declaration.
   * @param printer - TypeScript printer instance.
   * @param sourceFile - Source file from which the nodes are taken.
   * @returns The generated destructuring text.
   */
  private static genDestructElementTextForObjDecls(
    variableDeclarationMap: Map<string, string>,
    newObjectName: string,
    declarationFlags: ts.NodeFlags,
    printer: ts.Printer,
    sourceFile: ts.SourceFile
  ): string {
    let destructElementText: string = '';

    variableDeclarationMap.forEach((propertyName, variableName) => {
      // Create a property access expression for the new object
      const propertyAccessExpr = ts.factory.createPropertyAccessExpression(
        ts.factory.createIdentifier(newObjectName),
        ts.factory.createIdentifier(variableName)
      );

      // Create a variable declaration with the property access expression
      const variableDecl = ts.factory.createVariableDeclaration(
        ts.factory.createIdentifier(propertyName),
        undefined,
        undefined,
        propertyAccessExpr
      );

      // Create a variable statement for the variable declaration
      const variableStatement = ts.factory.createVariableStatement(
        undefined,
        ts.factory.createVariableDeclarationList([variableDecl], declarationFlags)
      );

      // Print the variable statement to text and append it
      const text = printer.printNode(ts.EmitHint.Unspecified, variableStatement, sourceFile);
      destructElementText += text;
    });

    return destructElementText;
  }

  /**
   * Creates autofix suggestions for destructuring assignment.
   * @param variableDeclaration - The variable or parameter declaration to fix.
   * @param newObjectName - Name of the new object to use for destructuring.
   * @param destructElementText - Generated text for destructuring elements.
   * @returns Array of autofix suggestions or undefined.
   */
  private static genAutofixForObjDecls(
    variableDeclaration: ts.VariableDeclaration | ts.ParameterDeclaration,
    newObjectName: string | undefined,
    destructElementText: string,
    isIdentifier: boolean
  ): Autofix[] | undefined {
    let variableNameReplaceText: Autofix;
    let destructElementReplaceText: Autofix;
    let autofix: Autofix[] | undefined = [];

    // Check if the initializer is a identifier
    if (isIdentifier) {
      destructElementReplaceText = {
        replacementText: destructElementText,
        start: variableDeclaration.parent.getStart(),
        end: variableDeclaration.parent.parent.getEnd()
      };
      autofix = [destructElementReplaceText];
    } else {
      // Create autofix suggestions for both variable name and destructuring
      variableNameReplaceText = {
        replacementText: newObjectName as string,
        start: variableDeclaration.name.getStart(),
        end: variableDeclaration.name.getEnd()
      };
      destructElementReplaceText = {
        replacementText: destructElementText,
        start: variableDeclaration.parent.parent.getEnd(),
        end: variableDeclaration.parent.parent.getEnd()
      };
      autofix = [variableNameReplaceText, destructElementReplaceText];
    }

    return autofix;
  }

  /**
   * Checks if the given variable declaration passes boundary checks for object declarations.
   *
   * @param faultId - The fault ID indicating the type of check to perform (e.g., destructuring parameter).
   * @param variableDeclaration - The variable or parameter declaration to check for boundary conditions.
   * @returns A boolean indicating if the declaration passes the boundary checks.
   */
  private static passBoundaryCheckForObjDecls(
    faultId: number,
    variableDeclaration: ts.VariableDeclaration | ts.ParameterDeclaration
  ): boolean {
    // Check if the fault ID is for a destructuring parameter or if the declaration has a spread operator
    if (
      faultId === FaultID.DestructuringParameter ||
      TsUtils.destructuringDeclarationHasSpreadOperator(variableDeclaration.name as ts.BindingPattern) ||
      TsUtils.destructuringDeclarationHasDefaultValue(variableDeclaration.name as ts.BindingPattern)
    ) {
      return false;
    }

    // If the initializer is an object literal expression, check its properties
    if (ts.isObjectLiteralExpression(variableDeclaration.initializer as ts.Node)) {
      const len = (variableDeclaration.initializer as ts.ObjectLiteralExpression).properties.length;
      if (len === 0) {
        // Return false if there are no properties
        return false;
      }
    }

    // Return true if all checks are passed
    return true;
  }

  /**
   ** Fixes object binding pattern declarations by generating appropriate autofix suggestions.
   * @param variableDeclaration - The variable or parameter declaration to fix.
   * @param faultId - The fault ID indicating the type of check to perform.
   * @returns Array of autofix suggestions or undefined.
   */
  fixObjectBindingPatternDeclarations(
    variableDeclaration: ts.VariableDeclaration | ts.ParameterDeclaration,
    faultId: number
  ): Autofix[] | undefined {
    if (!Autofixer.passBoundaryCheckForObjDecls(faultId, variableDeclaration)) {
      return undefined;
    }
    // Map to hold variable names and their corresponding property names
    const variableDeclarationMap: Map<string, string> = new Map();
    // If the declaration is an object binding pattern, extract names
    if (ts.isObjectBindingPattern(variableDeclaration.name)) {
      variableDeclaration.name.elements.forEach((element) => {
        if (!element.propertyName) {
          variableDeclarationMap.set(element.name.getText(), element.name.getText());
        } else {
          variableDeclarationMap.set((element.propertyName as ts.Identifier).text, element.name.getText());
        }
      });
    }
    const sourceFile = variableDeclaration.getSourceFile();
    let newObjectName: string | undefined;
    const isIdentifier = ts.isIdentifier(variableDeclaration.initializer as ts.Node);
    // If it is identifer, use its text as the new object name; otherwise, generate a unique name
    if (isIdentifier) {
      newObjectName = variableDeclaration.initializer?.getText();
    } else {
      newObjectName = TsUtils.generateUniqueName(this.destructObjNameGenerator, sourceFile);
    }
    if (!newObjectName) {
      return undefined;
    }
    const declarationFlags = ts.getCombinedNodeFlags(variableDeclaration);
    const destructElementText = Autofixer.genDestructElementTextForObjDecls(
      variableDeclarationMap,
      newObjectName,
      declarationFlags,
      this.printer,
      sourceFile
    );

    // Generate and return autofix suggestions for the object declarations
    return Autofixer.genAutofixForObjDecls(variableDeclaration, newObjectName, destructElementText, isIdentifier);
  }

  /**
   * Generates the text representation for destructuring elements in an array.
   * @param variableNames - Array of variable names corresponding to array elements.
   * @param newArrayName - Name of the new array to destructure.
   * @param declarationFlags - Flags for the variable declaration.
   * @param printer - TypeScript printer instance.
   * @param sourceFile - Source file from which the nodes are taken.
   * @returns The generated destructuring text.
   */
  private static genDestructElementTextForArrayDecls(
    variableNames: string[],
    newArrayName: string,
    declarationFlags: ts.NodeFlags,
    printer: ts.Printer,
    sourceFile: ts.SourceFile
  ): string {
    let destructElementText: string = '';
    const length = variableNames.length;

    // Iterate over the array of variable names
    for (let i = 0; i < length; i++) {
      const variableName = variableNames[i];

      // Create an element access expression for the new array
      const elementAccessExpr = ts.factory.createElementAccessExpression(
        ts.factory.createIdentifier(newArrayName),
        ts.factory.createNumericLiteral(i)
      );

      // Create a variable declaration with the element access expression
      const variableDecl = ts.factory.createVariableDeclaration(
        ts.factory.createIdentifier(variableName),
        undefined,
        undefined,
        elementAccessExpr
      );

      // Create a variable statement for the variable declaration
      const variableStatement = ts.factory.createVariableStatement(
        undefined,
        ts.factory.createVariableDeclarationList([variableDecl], declarationFlags)
      );

      // Print the variable statement to text and append it
      const text = printer.printNode(ts.EmitHint.Unspecified, variableStatement, sourceFile);
      destructElementText += text;
    }

    return destructElementText;
  }

  /**
   * Creates autofix suggestions for array destructuring assignment.
   * @param variableDeclaration - The variable or parameter declaration to fix.
   * @param newArrayName - Name of the new array to use for destructuring.
   * @param destructElementText - Generated text for destructuring elements.
   * @returns Array of autofix suggestions.
   */
  private static genAutofixForArrayDecls(
    variableDeclaration: ts.VariableDeclaration | ts.ParameterDeclaration,
    newArrayName: string | undefined,
    destructElementText: string,
    isIdentifierOrElementAccess: boolean
  ): Autofix[] {
    let variableNameReplaceText: Autofix;
    let destructElementReplaceText: Autofix;
    let autofix: Autofix[] = [];

    // Check if the initializer is an identifier or element access expression
    if (isIdentifierOrElementAccess) {
      destructElementReplaceText = {
        replacementText: destructElementText,
        start: variableDeclaration.parent.getStart(),
        end: variableDeclaration.parent.parent.getEnd()
      };
      autofix = [destructElementReplaceText];
    } else {
      // Create autofix suggestions for both variable name and destructuring
      variableNameReplaceText = {
        replacementText: newArrayName as string,
        start: variableDeclaration.name.getStart(),
        end: variableDeclaration.name.getEnd()
      };
      destructElementReplaceText = {
        replacementText: destructElementText,
        start: variableDeclaration.parent.parent.getEnd(),
        end: variableDeclaration.parent.parent.getEnd()
      };
      autofix = [variableNameReplaceText, destructElementReplaceText];
    }

    return autofix;
  }

  /**
   * Checks if the given variable declaration passes boundary checks for array or tuple declarations.
   *
   * @param variableDeclaration - A variable declaration or parameter declaration to be checked.
   * @param isArrayOrTuple - A boolean indicating whether the declaration is an array or tuple.
   * @returns A boolean indicating if the declaration passes the boundary checks.
   */
  private static passBoundaryCheckForArrayDecls(
    variableDeclaration: ts.VariableDeclaration | ts.ParameterDeclaration,
    isArrayOrTuple: boolean
  ): boolean {
    // If it's not an array/tuple or the declaration has a spread operator in destructuring
    if (
      !isArrayOrTuple ||
      TsUtils.destructuringDeclarationHasSpreadOperator(variableDeclaration.name as ts.BindingPattern) ||
      TsUtils.destructuringDeclarationHasDefaultValue(variableDeclaration.name as ts.BindingPattern)
    ) {
      // Return false if it fails the boundary check
      return false;
    }

    // Check if the array binding pattern has any empty elements
    if (TsUtils.checkArrayBindingHasEmptyElement(variableDeclaration.name as ts.ArrayBindingPattern)) {
      // Return false if it contains empty elements
      return false;
    }

    // Check if the initializer has the same dimension as expected
    if (!TsUtils.isSameDimension(variableDeclaration.initializer as ts.Node)) {
      return false;
    }

    // Return true if all checks are passed
    return true;
  }

  /**
   * Fixes array binding pattern declarations by generating appropriate autofix suggestions.
   *
   * @param variableDeclaration - The variable or parameter declaration to fix.
   * @param isArrayOrTuple - Flag indicating if the declaration is for an array or tuple.
   * @returns Array of autofix suggestions or undefined.
   */
  fixArrayBindingPatternDeclarations(
    variableDeclaration: ts.VariableDeclaration | ts.ParameterDeclaration,
    isArrayOrTuple: boolean
  ): Autofix[] | undefined {
    if (!Autofixer.passBoundaryCheckForArrayDecls(variableDeclaration, isArrayOrTuple)) {
      return undefined;
    }
    const variableNames: string[] = [];
    // If the declaration is an array binding pattern, extract variable names
    if (ts.isArrayBindingPattern(variableDeclaration.name)) {
      variableDeclaration.name.elements.forEach((element) => {
        variableNames.push(element.getText());
      });
    }

    const sourceFile = variableDeclaration.getSourceFile();
    let newArrayName: string | undefined = '';
    // Check if the initializer is either an identifier or an element access expression
    const isIdentifierOrElementAccess =
      ts.isIdentifier(variableDeclaration.initializer as ts.Node) ||
      ts.isElementAccessExpression(variableDeclaration.initializer as ts.Node);
    // If it is, use its text as the new array name; otherwise, generate a unique name
    if (isIdentifierOrElementAccess) {
      newArrayName = variableDeclaration.initializer?.getText();
    } else {
      newArrayName = TsUtils.generateUniqueName(this.destructArrayNameGenerator, sourceFile);
    }
    if (!newArrayName) {
      return undefined;
    }

    // Get the combined node flags for the variable declaration
    const declarationFlags = ts.getCombinedNodeFlags(variableDeclaration);
    // Generate the destructuring element text for the array declaration
    const destructElementText = Autofixer.genDestructElementTextForArrayDecls(
      variableNames,
      newArrayName,
      declarationFlags,
      this.printer,
      sourceFile
    );

    // Generate and return autofix suggestions for the array declarations
    return Autofixer.genAutofixForArrayDecls(
      variableDeclaration,
      newArrayName,
      destructElementText,
      isIdentifierOrElementAccess
    );
  }

  /**
   * Generates the text representation for destructuring assignments in an array.
   * @param variableNames - Array of variable names corresponding to array elements.
   * @param newArrayName - Name of the new array to use for destructuring.
   * @param printer - TypeScript printer instance.
   * @param sourceFile - Source file from which the nodes are taken.
   * @returns The generated destructuring assignment text.
   */
  private static genDestructElementTextForArrayAssignment(
    variableNames: string[],
    newArrayName: string | undefined,
    printer: ts.Printer,
    sourceFile: ts.SourceFile
  ): string {
    let destructElementText: string = '';
    const length = variableNames.length;

    // Iterate over the array of variable names
    for (let i = 0; i < length; i++) {
      const variableName = variableNames[i];

      // Create an element access expression for the new array
      const elementAccessExpr = ts.factory.createElementAccessExpression(
        ts.factory.createIdentifier(newArrayName as string),
        ts.factory.createNumericLiteral(i)
      );

      // Create a binary expression to assign the array element to the variable
      const assignmentExpr = ts.factory.createBinaryExpression(
        ts.factory.createIdentifier(variableName),
        ts.factory.createToken(ts.SyntaxKind.EqualsToken),
        elementAccessExpr
      );

      // Create an expression statement for the assignment expression
      const expressionStatement = ts.factory.createExpressionStatement(assignmentExpr);

      // Print the expression statement to text and append it
      const text = printer.printNode(ts.EmitHint.Unspecified, expressionStatement, sourceFile);
      destructElementText += text;
    }

    return destructElementText;
  }

  /**
   * Creates autofix suggestions for array destructuring assignment.
   * @param assignmentExpr - The binary expression for the assignment.
   * @param newArrayName - Name of the new array to use for destructuring.
   * @param destructElementText - Generated text for destructuring assignments.
   * @returns Array of autofix suggestions.
   */
  private static genAutofixForArrayAssignment(
    assignmentExpr: ts.BinaryExpression,
    newArrayName: string | undefined,
    destructElementText: string,
    isIdentifierOrElementAccess: boolean
  ): Autofix[] {
    let arrayNameReplaceText: Autofix;
    let destructElementReplaceText: Autofix;
    let autofix: Autofix[] = [];

    // Check if the right side of the assignment is an identifier or element access expression
    if (isIdentifierOrElementAccess) {
      destructElementReplaceText = {
        replacementText: destructElementText,
        start: assignmentExpr.parent.getStart(),
        end: assignmentExpr.parent.getEnd()
      };
      autofix = [destructElementReplaceText];
    } else {
      // Create autofix suggestions for both array name and destructuring assignments
      const keywordsLet = 'let ';
      arrayNameReplaceText = {
        replacementText: keywordsLet + newArrayName,
        start: assignmentExpr.left.getStart(),
        end: assignmentExpr.left.getEnd()
      };
      destructElementReplaceText = {
        replacementText: destructElementText,
        start: assignmentExpr.parent.getEnd(),
        end: assignmentExpr.parent.getEnd()
      };
      autofix = [arrayNameReplaceText, destructElementReplaceText];
    }

    return autofix;
  }

  /**
   * Checks if the given assignment expression passes boundary checks for array assignments.
   *
   * @param assignmentExpr - The assignment expression to check (a binary expression).
   * @param isArrayOrTuple - A boolean indicating if the assignment is for an array or tuple.
   * @returns A boolean indicating if the assignment passes the boundary checks.
   */
  private static passBoundaryCheckForArrayAssignment(
    assignmentExpr: ts.BinaryExpression,
    isArrayOrTuple: boolean
  ): boolean {
    // Return false if the assignment is not for an array or tuple
    if (!isArrayOrTuple) {
      return false;
    }

    // Check if the left side of the assignment is an array literal expression with a spread operator
    if (TsUtils.destructuringAssignmentHasSpreadOperator(assignmentExpr.left as ts.ArrayLiteralExpression)) {
      return false;
    }

    if (TsUtils.destructuringAssignmentHasDefaultValue(assignmentExpr.left as ts.ArrayLiteralExpression)) {
      return false;
    }

    // Check if the left side of the assignment has an empty element
    if (TsUtils.checkArrayLiteralHasEmptyElement(assignmentExpr.left as ts.ArrayLiteralExpression)) {
      return false;
    }

    // Check if the right side of the assignment has the same dimension as the left side
    if (!TsUtils.isSameDimension(assignmentExpr.right)) {
      return false;
    }

    // Return true if all boundary checks are passed
    return true;
  }

  /**
   * Fixes array binding pattern assignments by generating appropriate autofix suggestions.
   * @param assignmentExpr - The binary expression for the assignment.
   * @param isArrayOrTuple - Flag indicating if the assignment is for an array or tuple.
   * @returns Array of autofix suggestions or undefined.
   */
  fixArrayBindingPatternAssignment(
    assignmentExpr: ts.BinaryExpression,
    isArrayOrTuple: boolean
  ): Autofix[] | undefined {
    if (!Autofixer.passBoundaryCheckForArrayAssignment(assignmentExpr, isArrayOrTuple)) {
      return undefined;
    }
    // Collect variable names from array literal expression
    const variableNames: string[] = [];
    if (ts.isArrayLiteralExpression(assignmentExpr.left)) {
      assignmentExpr.left.elements.forEach((element) => {
        variableNames.push(element.getText());
      });
    }

    const sourceFile = assignmentExpr.getSourceFile();
    let newArrayName: string | undefined = '';
    const isIdentifierOrElementAccess =
      ts.isIdentifier(assignmentExpr.right) || ts.isElementAccessExpression(assignmentExpr.right as ts.Node);
    if (isIdentifierOrElementAccess) {
      newArrayName = assignmentExpr.right.getText();
    } else {
      newArrayName = TsUtils.generateUniqueName(this.destructArrayNameGenerator, sourceFile);
    }
    if (!newArrayName) {
      return undefined;
    }

    // Generate the text for destructuring assignments
    const destructElementText = Autofixer.genDestructElementTextForArrayAssignment(
      variableNames,
      newArrayName,
      this.printer,
      sourceFile
    );

    return Autofixer.genAutofixForArrayAssignment(
      assignmentExpr,
      newArrayName,
      destructElementText,
      isIdentifierOrElementAccess
    );
  }

  /**
   * Creates a mapping of variable declarations and needParentheses for object properties based on the provided binary expression.
   * @param binaryExpr - The binary expression containing the object literal.
   * @returns An object containing the variable declaration map and needParentheses indicating if property initializers are object literals.
   */
  private static genTsVarDeclMapAndFlags(binaryExpr: ts.BinaryExpression): {
    tsVarDeclMap: Map<string, string>;
    needParentheses: boolean[];
  } {
    const tsVarDeclMap: Map<string, string> = new Map();
    const needParentheses: boolean[] = [];

    // Check if the left side of the binary expression is an object literal
    if (ts.isObjectLiteralExpression(binaryExpr.left)) {
      binaryExpr.left.properties.forEach((property) => {
        // Handle property assignments with initializer
        if (ts.isPropertyAssignment(property)) {
          tsVarDeclMap.set(property.name?.getText(), property.initializer.getText());
          needParentheses.push(ts.isObjectLiteralExpression(property.initializer));
        } else if (ts.isShorthandPropertyAssignment(property)) {
          tsVarDeclMap.set(property.name?.getText(), property.name.getText());
          needParentheses.push(false);
        }
      });
    }

    return { tsVarDeclMap, needParentheses };
  }

  /**
   * Generates the text for destructuring assignments based on the variable declaration map and needParentheses.
   * @param tsVarDeclMap - Map of variable names to property names.
   * @param needParentheses - Array of needParentheses indicating if property initializers are object literals.
   * @param newObjName - The name of the new object to use for destructuring.
   * @param binaryExpr - The binary expression representing the destructuring.
   * @param printer - TypeScript printer instance for printing nodes.
   * @returns The generated text for destructuring assignments.
   */
  private static genDestructElementTextForObjAssignment(
    tsVarDeclMap: Map<string, string>,
    needParentheses: boolean[],
    newObjName: string,
    binaryExpr: ts.BinaryExpression,
    printer: ts.Printer
  ): string {
    let destructElementText: string = '';
    let index: number = 0;

    // Iterate through the variable declaration map to generate destructuring assignments
    tsVarDeclMap.forEach((propertyName, variableName) => {
      // Create property access expression for the new object
      const propAccessExpr = ts.factory.createPropertyAccessExpression(
        ts.factory.createIdentifier(newObjName),
        ts.factory.createIdentifier(variableName)
      );
      // Create binary expression for assignment
      const assignmentExpr = ts.factory.createBinaryExpression(
        ts.factory.createIdentifier(propertyName),
        ts.factory.createToken(ts.SyntaxKind.EqualsToken),
        propAccessExpr
      );
      // Create statement for the assignment expression, with or without parentheses based on the flag
      const statement = needParentheses[index] ?
        ts.factory.createExpressionStatement(ts.factory.createParenthesizedExpression(assignmentExpr)) :
        ts.factory.createExpressionStatement(assignmentExpr);

      // Append the generated text for the destructuring assignment
      destructElementText += printer.printNode(ts.EmitHint.Unspecified, statement, binaryExpr.getSourceFile());

      index++;
    });

    return destructElementText;
  }

  /**
   * Creates the replacement text for the variable declaration name.
   * @param binaryExpr - The binary expression containing the object literal or call expression.
   * @param newObjName - The new object name to be used in the replacement.
   * @param printer - TypeScript printer instance for printing nodes.
   * @returns The replacement text for the variable declaration name.
   */
  private static genDeclNameReplaceTextForObjAssignment(
    binaryExpr: ts.BinaryExpression,
    newObjName: string,
    printer: ts.Printer
  ): string {
    let declNameReplaceText = '';

    // create variableDeclList and get declNameReplaceText text
    const variableDecl = ts.factory.createVariableDeclaration(
      ts.factory.createIdentifier(newObjName),
      undefined,
      undefined,
      binaryExpr.right
    );
    const variableDeclList = ts.factory.createVariableDeclarationList([variableDecl], ts.NodeFlags.Let);
    declNameReplaceText = printer.printNode(ts.EmitHint.Unspecified, variableDeclList, binaryExpr.getSourceFile());

    return declNameReplaceText;
  }

  /**
   * Creates autofix suggestions for object literal destructuring assignments.
   * @param binaryExpr - The binary expression containing the destructuring assignment.
   * @param declNameReplaceText - Replacement text for the variable declaration name.
   * @param destructElementText - Generated text for destructuring assignments.
   * @returns Array of autofix suggestions or undefined if no fixes are needed.
   */
  private static createAutofixForObjAssignment(
    binaryExpr: ts.BinaryExpression,
    declNameReplaceText: string,
    destructElementText: string,
    isIdentifier: boolean
  ): Autofix[] | undefined {
    let declNameReplaceTextAutofix: Autofix;
    let destructElementReplaceTextAutofix: Autofix;
    let autofix: Autofix[] | undefined;

    // Check if the right side of the binary expression is identifer
    if (isIdentifier) {
      destructElementReplaceTextAutofix = {
        replacementText: destructElementText,
        start: binaryExpr.parent.parent.getStart(),
        end: binaryExpr.parent.parent.getEnd()
      };
      autofix = [destructElementReplaceTextAutofix];
    } else {
      declNameReplaceTextAutofix = {
        replacementText: declNameReplaceText,
        start: binaryExpr.parent.getStart(),
        end: binaryExpr.parent.getEnd()
      };
      destructElementReplaceTextAutofix = {
        replacementText: destructElementText,
        start: binaryExpr.parent.parent.getEnd(),
        end: binaryExpr.parent.parent.getEnd()
      };
      autofix = [declNameReplaceTextAutofix, destructElementReplaceTextAutofix];
    }

    return autofix;
  }

  /**
   * Checks if the given assignment expression passes boundary checks for object assignments.
   *
   * @param binaryExpr - The binary expression representing the assignment to check.
   * @returns A boolean indicating if the assignment passes the boundary checks.
   */
  private static passBoundaryCheckForObjAssignment(binaryExpr: ts.BinaryExpression): boolean {
    // Check for spread operator in destructuring assignment on the left side
    if (TsUtils.destructuringAssignmentHasSpreadOperator(binaryExpr.left as ts.ObjectLiteralExpression)) {
      return false;
    }

    if (TsUtils.destructuringAssignmentHasDefaultValue(binaryExpr.left as ts.ObjectLiteralExpression)) {
      return false;
    }

    // Check if the right side is an object literal expression with no properties
    if (ts.isObjectLiteralExpression(binaryExpr.right) && binaryExpr.right.properties.length === 0) {
      return false;
    }

    // Return true if all boundary checks are passed
    return true;
  }

  /**
   * Fixes object literal expression destructuring assignments by generating autofix suggestions.
   * @param binaryExpr - The binary expression representing the destructuring assignment.
   * @returns Array of autofix suggestions or undefined if no fixes are needed.
   */
  fixObjectLiteralExpressionDestructAssignment(binaryExpr: ts.BinaryExpression): Autofix[] | undefined {
    if (!Autofixer.passBoundaryCheckForObjAssignment(binaryExpr)) {
      return undefined;
    }
    // Create a mapping of variable declarations and needParentheses
    const { tsVarDeclMap, needParentheses } = Autofixer.genTsVarDeclMapAndFlags(binaryExpr);

    const sourceFile = binaryExpr.getSourceFile();
    let newObjName: string | undefined = '';
    // Generate a unique name if right expression is not identifer
    const isIdentifier = ts.isIdentifier(binaryExpr.right);
    if (isIdentifier) {
      newObjName = binaryExpr.right?.getText();
    } else {
      newObjName = TsUtils.generateUniqueName(this.destructObjNameGenerator, sourceFile);
    }
    if (!newObjName) {
      return undefined;
    }
    // Create the text for destructuring elements
    const destructElementText = Autofixer.genDestructElementTextForObjAssignment(
      tsVarDeclMap,
      needParentheses,
      newObjName,
      binaryExpr,
      this.printer
    );

    // Create the replacement text for the variable declaration name
    const declNameReplaceText = Autofixer.genDeclNameReplaceTextForObjAssignment(binaryExpr, newObjName, this.printer);

    // Generate autofix suggestions
    return Autofixer.createAutofixForObjAssignment(binaryExpr, declNameReplaceText, destructElementText, isIdentifier);
  }

  fixLiteralAsPropertyNamePropertyAssignment(node: ts.PropertyAssignment): Autofix[] | undefined {
    const contextualType = this.typeChecker.getContextualType(node.parent);
    if (contextualType === undefined) {
      return undefined;
    }

    const symbol = this.utils.getPropertySymbol(contextualType, node);
    if (symbol === undefined) {
      return undefined;
    }

    return this.renameSymbolAsIdentifier(symbol);
  }

  fixLiteralAsPropertyNamePropertyName(node: ts.PropertyName): Autofix[] | undefined {
    const symbol = this.typeChecker.getSymbolAtLocation(node);
    if (symbol === undefined) {
      return undefined;
    }

    return this.renameSymbolAsIdentifier(symbol);
  }

  fixPropertyAccessByIndex(node: ts.ElementAccessExpression): Autofix[] | undefined {
    const symbol = this.typeChecker.getSymbolAtLocation(node.argumentExpression);
    if (symbol === undefined) {
      return undefined;
    }

    return this.renameSymbolAsIdentifier(symbol);
  }

  private renameSymbolAsIdentifier(symbol: ts.Symbol): Autofix[] | undefined {
    if (this.renameSymbolAsIdentifierCache.has(symbol)) {
      return this.renameSymbolAsIdentifierCache.get(symbol);
    }

    if (!TsUtils.isPropertyOfInternalClassOrInterface(symbol)) {
      this.renameSymbolAsIdentifierCache.set(symbol, undefined);
      return undefined;
    }

    const newName = this.utils.findIdentifierNameForSymbol(symbol);
    if (newName === undefined) {
      this.renameSymbolAsIdentifierCache.set(symbol, undefined);
      return undefined;
    }

    let result: Autofix[] | undefined = [];
    this.symbolCache.getReferences(symbol).forEach((node) => {
      if (result === undefined) {
        return;
      }

      let autofix: Autofix[] | undefined;
      if (ts.isPropertyDeclaration(node) || ts.isPropertyAssignment(node) || ts.isPropertySignature(node)) {
        autofix = Autofixer.renamePropertyName(node.name, newName);
      } else if (ts.isElementAccessExpression(node)) {
        autofix = Autofixer.renameElementAccessExpression(node, newName);
      }

      if (autofix === undefined) {
        result = undefined;
        return;
      }

      result.push(...autofix);
    });
    if (!result?.length) {
      result = undefined;
    }

    this.renameSymbolAsIdentifierCache.set(symbol, result);
    return result;
  }

  private readonly renameSymbolAsIdentifierCache = new Map<ts.Symbol, Autofix[] | undefined>();

  private static renamePropertyName(node: ts.PropertyName, newName: string): Autofix[] | undefined {
    if (ts.isComputedPropertyName(node)) {
      return undefined;
    }

    if (ts.isMemberName(node)) {
      if (ts.idText(node) !== newName) {
        return undefined;
      }

      return [];
    }

    return [{ replacementText: newName, start: node.getStart(), end: node.getEnd() }];
  }

  private static renameElementAccessExpression(
    node: ts.ElementAccessExpression,
    newName: string
  ): Autofix[] | undefined {
    const argExprKind = node.argumentExpression.kind;
    if (argExprKind !== ts.SyntaxKind.NumericLiteral && argExprKind !== ts.SyntaxKind.StringLiteral) {
      return undefined;
    }

    return [
      {
        replacementText: node.expression.getText() + '.' + newName,
        start: node.getStart(),
        end: node.getEnd()
      }
    ];
  }

  fixFunctionExpression(
    funcExpr: ts.FunctionExpression,
    // eslint-disable-next-line default-param-last
    retType: ts.TypeNode | undefined = funcExpr.type,
    modifiers: readonly ts.Modifier[] | undefined,
    isGenerator: boolean,
    hasUnfixableReturnType: boolean
  ): Autofix[] | undefined {
    const hasThisKeyword = scopeContainsThis(funcExpr.body);
    const isCalledRecursively = this.utils.isFunctionCalledRecursively(funcExpr);
    if (isGenerator || hasThisKeyword || isCalledRecursively || hasUnfixableReturnType) {
      return undefined;
    }

    let arrowFunc: ts.Expression = ts.factory.createArrowFunction(
      modifiers,
      funcExpr.typeParameters,
      funcExpr.parameters,
      retType,
      ts.factory.createToken(ts.SyntaxKind.EqualsGreaterThanToken),
      funcExpr.body
    );
    if (Autofixer.needsParentheses(funcExpr)) {
      arrowFunc = ts.factory.createParenthesizedExpression(arrowFunc);
    }
    const text = this.printer.printNode(ts.EmitHint.Unspecified, arrowFunc, funcExpr.getSourceFile());
    return [{ start: funcExpr.getStart(), end: funcExpr.getEnd(), replacementText: text }];
  }

  private static isNodeInWhileOrIf(node: ts.Node): boolean {
    return (
      node.kind === ts.SyntaxKind.WhileStatement ||
      node.kind === ts.SyntaxKind.DoStatement ||
      node.kind === ts.SyntaxKind.IfStatement
    );
  }

  private static isNodeInForLoop(node: ts.Node): boolean {
    return (
      node.kind === ts.SyntaxKind.ForInStatement ||
      node.kind === ts.SyntaxKind.ForOfStatement ||
      node.kind === ts.SyntaxKind.ForStatement
    );
  }

  private static parentInFor(node: ts.Node): ts.Node | undefined {
    let parentNode = node.parent;
    while (parentNode) {
      if (Autofixer.isNodeInForLoop(parentNode)) {
        return parentNode;
      }
      parentNode = parentNode.parent;
    }
    return undefined;
  }

  private static parentInCaseOrWhile(varDeclList: ts.VariableDeclarationList): boolean {
    let parentNode: ts.Node = varDeclList.parent;
    while (parentNode) {
      if (parentNode.kind === ts.SyntaxKind.CaseClause || Autofixer.isNodeInWhileOrIf(parentNode)) {
        return false;
      }
      parentNode = parentNode.parent;
    }
    return true;
  }

  private static isFunctionLikeDeclarationKind(node: ts.Node): boolean {
    switch (node.kind) {
      case ts.SyntaxKind.FunctionDeclaration:
      case ts.SyntaxKind.MethodDeclaration:
      case ts.SyntaxKind.Constructor:
      case ts.SyntaxKind.GetAccessor:
      case ts.SyntaxKind.SetAccessor:
      case ts.SyntaxKind.FunctionExpression:
      case ts.SyntaxKind.ArrowFunction:
        return true;
      default:
        return false;
    }
  }

  private static findVarScope(node: ts.Node): ts.Node {
    while (node !== undefined) {
      if (node.kind === ts.SyntaxKind.Block || node.kind === ts.SyntaxKind.SourceFile) {
        break;
      }
      // eslint-disable-next-line no-param-reassign
      node = node.parent;
    }
    return node;
  }

  private static varHasScope(node: ts.Node, scope: ts.Node): boolean {
    while (node !== undefined) {
      if (node === scope) {
        return true;
      }
      // eslint-disable-next-line no-param-reassign
      node = node.parent;
    }
    return false;
  }

  private static varInFunctionForScope(node: ts.Node, scope: ts.Node): boolean {
    while (node !== undefined) {
      if (Autofixer.isFunctionLikeDeclarationKind(node)) {
        break;
      }
      // eslint-disable-next-line no-param-reassign
      node = node.parent;
    }
    // node now Function like declaration

    // node need to check that function like declaration is in scope
    if (Autofixer.varHasScope(node, scope)) {
      // var use is in function scope, which is in for scope
      return true;
    }
    return false;
  }

  private static selfDeclared(decl: ts.Node, ident: ts.Node): boolean {
    // Do not check the same node
    if (ident === decl) {
      return false;
    }

    while (ident !== undefined) {
      if (ident.kind === ts.SyntaxKind.VariableDeclaration) {
        const declName = (ident as ts.VariableDeclaration).name;
        if (declName === decl) {
          return true;
        }
      }
      // eslint-disable-next-line no-param-reassign
      ident = ident.parent;
    }
    return false;
  }

  private static analizeTDZ(decl: ts.VariableDeclaration, identifiers: ts.Node[]): boolean {
    for (const ident of identifiers) {
      if (Autofixer.selfDeclared(decl.name, ident)) {
        return false;
      }
      if (ident.pos < decl.pos) {
        return false;
      }
    }
    return true;
  }

  private static analizeScope(decl: ts.VariableDeclaration, identifiers: ts.Node[]): boolean {
    const scope = Autofixer.findVarScope(decl);
    if (scope === undefined) {
      return false;
    } else if (scope.kind === ts.SyntaxKind.Block) {
      for (const ident of identifiers) {
        if (!Autofixer.varHasScope(ident, scope)) {
          return false;
        }
      }
    } else if (scope.kind === ts.SyntaxKind.SourceFile) {
      // Do nothing
    } else {
      // Unreachable, but check it
      return false;
    }
    return true;
  }

  private static analizeFor(decl: ts.VariableDeclaration, identifiers: ts.Node[]): boolean {
    const forNode = Autofixer.parentInFor(decl);
    if (forNode) {
      // analize that var is initialized
      if (forNode.kind === ts.SyntaxKind.ForInStatement || forNode.kind === ts.SyntaxKind.ForOfStatement) {
        const typedForNode = forNode as ts.ForInOrOfStatement;
        const forVarDeclarations = (typedForNode.initializer as ts.VariableDeclarationList).declarations;
        if (forVarDeclarations.length !== 1) {
          return false;
        }
        const forVarDecl = forVarDeclarations[0];

        // our goal to skip declarations in for of/in initializer
        if (forVarDecl !== decl && decl.initializer === undefined) {
          return false;
        }
      } else if (decl.initializer === undefined) {
        return false;
      }

      // analize that var uses are only in function block
      for (const ident of identifiers) {
        if (ident !== decl && !Autofixer.varHasScope(ident, forNode)) {
          return false;
        }
      }

      // analize that var is not in function
      for (const ident of identifiers) {
        if (ident !== decl && Autofixer.varInFunctionForScope(ident, forNode)) {
          return false;
        }
      }
    }
    return true;
  }

  private checkVarDeclarations(varDeclList: ts.VariableDeclarationList): boolean {
    for (const decl of varDeclList.declarations) {
      const symbol = this.typeChecker.getSymbolAtLocation(decl.name);
      if (!symbol) {
        return false;
      }

      const identifiers = this.symbolCache.getReferences(symbol);

      const declLength = symbol.declarations?.length;
      if (!declLength || declLength >= 2) {
        return false;
      }

      // Check for var use in tdz oe self declaration
      if (!Autofixer.analizeTDZ(decl, identifiers)) {
        return false;
      }

      // Has use outside scope of declaration?
      if (!Autofixer.analizeScope(decl, identifiers)) {
        return false;
      }

      // For analisys
      if (!Autofixer.analizeFor(decl, identifiers)) {
        return false;
      }

      if (symbol.getName() === 'let') {
        return false;
      }
    }
    return true;
  }

  private canAutofixNoVar(varDeclList: ts.VariableDeclarationList): boolean {
    if (!Autofixer.parentInCaseOrWhile(varDeclList)) {
      return false;
    }

    if (!this.checkVarDeclarations(varDeclList)) {
      return false;
    }

    return true;
  }

  fixVarDeclaration(node: ts.VariableDeclarationList): Autofix[] | undefined {
    const newNode = ts.factory.createVariableDeclarationList(node.declarations, ts.NodeFlags.Let);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, newNode, node.getSourceFile());
    return this.canAutofixNoVar(node) ?
      [{ start: node.getStart(), end: node.getEnd(), replacementText: text }] :
      undefined;
  }

  private getFixReturnTypeArrowFunction(funcLikeDecl: ts.FunctionLikeDeclaration, typeNode: ts.TypeNode): string {
    if (!funcLikeDecl.body) {
      return '';
    }
    const node = ts.factory.createArrowFunction(
      undefined,
      funcLikeDecl.typeParameters,
      funcLikeDecl.parameters,
      typeNode,
      ts.factory.createToken(ts.SyntaxKind.EqualsGreaterThanToken),
      funcLikeDecl.body
    );
    return this.printer.printNode(ts.EmitHint.Unspecified, node, funcLikeDecl.getSourceFile());
  }

  fixMissingReturnType(funcLikeDecl: ts.FunctionLikeDeclaration, typeNode: ts.TypeNode): Autofix[] {
    if (ts.isArrowFunction(funcLikeDecl)) {
      const text = this.getFixReturnTypeArrowFunction(funcLikeDecl, typeNode);
      const startPos = funcLikeDecl.getStart();
      const endPos = funcLikeDecl.getEnd();
      return [{ start: startPos, end: endPos, replacementText: text }];
    }
    const text = ': ' + this.printer.printNode(ts.EmitHint.Unspecified, typeNode, funcLikeDecl.getSourceFile());
    const pos = Autofixer.getReturnTypePosition(funcLikeDecl);
    return [{ start: pos, end: pos, replacementText: text }];
  }

  dropTypeOnVarDecl(varDecl: ts.VariableDeclaration): Autofix[] {
    const newVarDecl = ts.factory.createVariableDeclaration(varDecl.name, undefined, undefined, undefined);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, newVarDecl, varDecl.getSourceFile());
    return [{ start: varDecl.getStart(), end: varDecl.getEnd(), replacementText: text }];
  }

  fixTypeAssertion(typeAssertion: ts.TypeAssertion): Autofix[] {
    const asExpr = ts.factory.createAsExpression(typeAssertion.expression, typeAssertion.type);
    const text = this.nonCommentPrinter.printNode(ts.EmitHint.Unspecified, asExpr, typeAssertion.getSourceFile());
    return [{ start: typeAssertion.getStart(), end: typeAssertion.getEnd(), replacementText: text }];
  }

  fixCommaOperator(tsNode: ts.Node): Autofix[] {
    const tsExprNode = tsNode as ts.BinaryExpression;
    const text = this.recursiveCommaOperator(tsExprNode);
    return [{ start: tsExprNode.parent.getFullStart(), end: tsExprNode.parent.getEnd(), replacementText: text }];
  }

  private recursiveCommaOperator(tsExprNode: ts.BinaryExpression): string {
    let text = '';
    if (tsExprNode.operatorToken.kind !== ts.SyntaxKind.CommaToken) {
      return tsExprNode.getFullText() + ';';
    }

    if (tsExprNode.left.kind === ts.SyntaxKind.BinaryExpression) {
      text += this.recursiveCommaOperator(tsExprNode.left as ts.BinaryExpression);
      text += '\n' + tsExprNode.right.getFullText() + ';';
    } else {
      const leftText = tsExprNode.left.getFullText();
      const rightText = tsExprNode.right.getFullText();
      text = leftText + ';\n' + rightText + ';';
    }

    return text;
  }

  private getEnumMembers(node: ts.Node, enumDeclsInFile: ts.Declaration[], result: Autofix[] | undefined): void {
    if (result === undefined || !ts.isEnumDeclaration(node)) {
      return;
    }

    if (result.length) {
      result.push({ start: node.getStart(), end: node.getEnd(), replacementText: '' });
      return;
    }

    const members: ts.EnumMember[] = [];
    for (const decl of enumDeclsInFile) {
      for (const member of (decl as ts.EnumDeclaration).members) {
        if (
          member.initializer &&
          member.initializer.kind !== ts.SyntaxKind.NumericLiteral &&
          member.initializer.kind !== ts.SyntaxKind.StringLiteral
        ) {
          result = undefined;
          return;
        }
      }
      members.push(...(decl as ts.EnumDeclaration).members);
    }

    const fullEnum = ts.factory.createEnumDeclaration(node.modifiers, node.name, members);
    const fullText = this.printer.printNode(ts.EmitHint.Unspecified, fullEnum, node.getSourceFile());
    result.push({ start: node.getStart(), end: node.getEnd(), replacementText: fullText });
  }

  fixEnumMerging(enumSymbol: ts.Symbol, enumDeclsInFile: ts.Declaration[]): Autofix[] | undefined {
    if (this.enumMergingCache.has(enumSymbol)) {
      return this.enumMergingCache.get(enumSymbol);
    }

    if (enumDeclsInFile.length <= 1) {
      this.enumMergingCache.set(enumSymbol, undefined);
      return undefined;
    }

    let result: Autofix[] | undefined = [];
    this.symbolCache.getReferences(enumSymbol).forEach((node) => {
      this.getEnumMembers(node, enumDeclsInFile, result);
    });
    if (!result?.length) {
      result = undefined;
    }

    this.enumMergingCache.set(enumSymbol, result);
    return result;
  }

  private readonly enumMergingCache = new Map<ts.Symbol, Autofix[] | undefined>();

  private readonly printer: ts.Printer = ts.createPrinter({
    omitTrailingSemicolon: false,
    removeComments: false,
    newLine: ts.NewLineKind.LineFeed
  });

  private readonly nonCommentPrinter: ts.Printer = ts.createPrinter({
    omitTrailingSemicolon: false,
    removeComments: true,
    newLine: ts.NewLineKind.LineFeed
  });

  private static getReturnTypePosition(funcLikeDecl: ts.FunctionLikeDeclaration): number {
    if (funcLikeDecl.body) {

      /*
       * Find position of the first node or token that follows parameters.
       * After that, iterate over child nodes in reverse order, until found
       * first closing parenthesis.
       */
      const postParametersPosition = ts.isArrowFunction(funcLikeDecl) ?
        funcLikeDecl.equalsGreaterThanToken.getStart() :
        funcLikeDecl.body.getStart();

      const children = funcLikeDecl.getChildren();
      for (let i = children.length - 1; i >= 0; i--) {
        const child = children[i];
        if (child.kind === ts.SyntaxKind.CloseParenToken && child.getEnd() <= postParametersPosition) {
          return child.getEnd();
        }
      }
    }

    // Shouldn't get here.
    return -1;
  }

  private static needsParentheses(node: ts.FunctionExpression): boolean {
    const parent = node.parent;
    return (
      ts.isPrefixUnaryExpression(parent) ||
      ts.isPostfixUnaryExpression(parent) ||
      ts.isPropertyAccessExpression(parent) ||
      ts.isElementAccessExpression(parent) ||
      ts.isTypeOfExpression(parent) ||
      ts.isVoidExpression(parent) ||
      ts.isAwaitExpression(parent) ||
      ts.isCallExpression(parent) && node === parent.expression ||
      ts.isBinaryExpression(parent) && !isAssignmentOperator(parent.operatorToken)
    );
  }

  fixCtorParameterProperties(
    ctorDecl: ts.ConstructorDeclaration,
    paramTypes: ts.TypeNode[] | undefined
  ): Autofix[] | undefined {
    if (paramTypes === undefined) {
      return undefined;
    }

    const fieldInitStmts: ts.Statement[] = [];
    const newFieldPos = ctorDecl.getStart();
    const autofixes: Autofix[] = [{ start: newFieldPos, end: newFieldPos, replacementText: '' }];

    for (let i = 0; i < ctorDecl.parameters.length; i++) {
      this.fixCtorParameterPropertiesProcessParam(
        ctorDecl.parameters[i],
        paramTypes[i],
        ctorDecl.getSourceFile(),
        fieldInitStmts,
        autofixes
      );
    }

    // Note: Bodyless ctors can't have parameter properties.
    if (ctorDecl.body) {
      const newBody = ts.factory.createBlock(fieldInitStmts.concat(ctorDecl.body.statements), true);
      const newBodyText = this.printer.printNode(ts.EmitHint.Unspecified, newBody, ctorDecl.getSourceFile());
      autofixes.push({ start: ctorDecl.body.getStart(), end: ctorDecl.body.getEnd(), replacementText: newBodyText });
    }

    return autofixes;
  }

  private fixCtorParameterPropertiesProcessParam(
    param: ts.ParameterDeclaration,
    paramType: ts.TypeNode,
    sourceFile: ts.SourceFile,
    fieldInitStmts: ts.Statement[],
    autofixes: Autofix[]
  ): void {
    // Parameter property can not be a destructuring parameter.
    if (!ts.isIdentifier(param.name)) {
      return;
    }

    if (this.utils.hasAccessModifier(param)) {
      const propIdent = ts.factory.createIdentifier(param.name.text);

      const newFieldNode = ts.factory.createPropertyDeclaration(
        ts.getModifiers(param),
        propIdent,
        undefined,
        paramType,
        undefined
      );
      const newFieldText = this.printer.printNode(ts.EmitHint.Unspecified, newFieldNode, sourceFile) + '\n';
      autofixes[0].replacementText += newFieldText;

      const newParamDecl = ts.factory.createParameterDeclaration(
        undefined,
        undefined,
        param.name,
        param.questionToken,
        param.type,
        param.initializer
      );
      const newParamText = this.printer.printNode(ts.EmitHint.Unspecified, newParamDecl, sourceFile);
      autofixes.push({ start: param.getStart(), end: param.getEnd(), replacementText: newParamText });

      fieldInitStmts.push(
        ts.factory.createExpressionStatement(
          ts.factory.createAssignment(
            ts.factory.createPropertyAccessExpression(ts.factory.createThis(), propIdent),
            propIdent
          )
        )
      );
    }
  }

  fixPrivateIdentifier(node: ts.PrivateIdentifier): Autofix[] | undefined {
    const classMember = this.typeChecker.getSymbolAtLocation(node);
    if (!classMember || (classMember.getFlags() & ts.SymbolFlags.ClassMember) === 0 || !classMember.valueDeclaration) {
      return undefined;
    }

    if (this.privateIdentifierCache.has(classMember)) {
      return this.privateIdentifierCache.get(classMember);
    }

    const memberDecl = classMember.valueDeclaration as ts.ClassElement;
    const parentDecl = memberDecl.parent;
    if (!ts.isClassLike(parentDecl) || this.utils.classMemberHasDuplicateName(memberDecl, parentDecl, true)) {
      this.privateIdentifierCache.set(classMember, undefined);
      return undefined;
    }

    let result: Autofix[] | undefined = [];
    this.symbolCache.getReferences(classMember).forEach((ident) => {
      if (ts.isPrivateIdentifier(ident)) {
        result!.push(this.fixSinglePrivateIdentifier(ident));
      }
    });
    if (!result.length) {
      result = undefined;
    }

    this.privateIdentifierCache.set(classMember, result);
    return result;
  }

  private isFunctionDeclarationFirst(tsFunctionDeclaration: ts.FunctionDeclaration): boolean {
    if (tsFunctionDeclaration.name === undefined) {
      return false;
    }

    const symbol = this.typeChecker.getSymbolAtLocation(tsFunctionDeclaration.name);
    if (symbol === undefined) {
      return false;
    }

    let minPos = tsFunctionDeclaration.pos;
    this.symbolCache.getReferences(symbol).forEach((ident) => {
      if (ident.pos < minPos) {
        minPos = ident.pos;
      }
    });

    return minPos >= tsFunctionDeclaration.pos;
  }

  fixNestedFunction(tsFunctionDeclaration: ts.FunctionDeclaration): Autofix[] | undefined {
    const isGenerator = tsFunctionDeclaration.asteriskToken !== undefined;
    const hasThisKeyword =
      tsFunctionDeclaration.body === undefined ? false : scopeContainsThis(tsFunctionDeclaration.body);
    const canBeFixed = !isGenerator && !hasThisKeyword;
    if (!canBeFixed) {
      return undefined;
    }

    const name = tsFunctionDeclaration.name?.escapedText;
    const type = tsFunctionDeclaration.type;
    const body = tsFunctionDeclaration.body;
    if (!name || !type || !body) {
      return undefined;
    }

    // Check only illegal decorators, cause all decorators for function declaration are illegal
    if (ts.getIllegalDecorators(tsFunctionDeclaration)) {
      return undefined;
    }

    if (!this.isFunctionDeclarationFirst(tsFunctionDeclaration)) {
      return undefined;
    }

    const typeParameters = tsFunctionDeclaration.typeParameters;
    const parameters = tsFunctionDeclaration.parameters;
    const modifiers = ts.getModifiers(tsFunctionDeclaration);

    const token = ts.factory.createToken(ts.SyntaxKind.EqualsGreaterThanToken);
    const typeDecl = ts.factory.createFunctionTypeNode(typeParameters, parameters, type);
    const arrowFunc = ts.factory.createArrowFunction(modifiers, typeParameters, parameters, type, token, body);

    const declaration: ts.VariableDeclaration = ts.factory.createVariableDeclaration(
      name,
      undefined,
      typeDecl,
      arrowFunc
    );
    const list: ts.VariableDeclarationList = ts.factory.createVariableDeclarationList([declaration], ts.NodeFlags.Let);

    const statement = ts.factory.createVariableStatement(modifiers, list);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, statement, tsFunctionDeclaration.getSourceFile());
    return [{ start: tsFunctionDeclaration.getStart(), end: tsFunctionDeclaration.getEnd(), replacementText: text }];
  }

  fixMultipleStaticBlocks(nodes: ts.Node[]): Autofix[] | undefined {
    const autofix: Autofix[] | undefined = [];
    let body = (nodes[0] as ts.ClassStaticBlockDeclaration).body;
    let bodyStatements: ts.Statement[] = [];
    bodyStatements = bodyStatements.concat(body.statements);
    for (let i = 1; i < nodes.length; i++) {
      bodyStatements = bodyStatements.concat((nodes[i] as ts.ClassStaticBlockDeclaration).body.statements);
      autofix[i] = { start: nodes[i].getStart(), end: nodes[i].getEnd(), replacementText: '' };
    }
    body = ts.factory.createBlock(bodyStatements, true);
    // static blocks shouldn't have modifiers
    const statickBlock = ts.factory.createClassStaticBlockDeclaration(body);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, statickBlock, nodes[0].getSourceFile());
    autofix[0] = { start: nodes[0].getStart(), end: nodes[0].getEnd(), replacementText: text };
    return autofix;
  }

  private readonly privateIdentifierCache = new Map<ts.Symbol, Autofix[] | undefined>();

  private fixSinglePrivateIdentifier(ident: ts.PrivateIdentifier): Autofix {
    if (
      ts.isPropertyDeclaration(ident.parent) ||
      ts.isMethodDeclaration(ident.parent) ||
      ts.isGetAccessorDeclaration(ident.parent) ||
      ts.isSetAccessorDeclaration(ident.parent)
    ) {
      // Note: 'private' modifier should always be first.
      const mods = ts.getModifiers(ident.parent);
      const newMods: ts.Modifier[] = [ts.factory.createModifier(ts.SyntaxKind.PrivateKeyword)];
      if (mods) {
        for (const mod of mods) {
          newMods.push(ts.factory.createModifier(mod.kind));
        }
      }

      const newName = ident.text.slice(1, ident.text.length);
      const newDecl = Autofixer.replacePrivateIdentInDeclarationName(newMods, newName, ident.parent);
      const text = this.printer.printNode(ts.EmitHint.Unspecified, newDecl, ident.getSourceFile());
      return { start: ident.parent.getStart(), end: ident.parent.getEnd(), replacementText: text };
    }

    return {
      start: ident.getStart(),
      end: ident.getEnd(),
      replacementText: ident.text.slice(1, ident.text.length)
    };
  }

  private static replacePrivateIdentInDeclarationName(
    mods: ts.Modifier[],
    name: string,
    oldDecl: ts.PropertyDeclaration | ts.MethodDeclaration | ts.GetAccessorDeclaration | ts.SetAccessorDeclaration
  ): ts.Declaration {
    if (ts.isPropertyDeclaration(oldDecl)) {
      return ts.factory.createPropertyDeclaration(
        mods,
        ts.factory.createIdentifier(name),
        oldDecl.questionToken ?? oldDecl.exclamationToken,
        oldDecl.type,
        oldDecl.initializer
      );
    } else if (ts.isMethodDeclaration(oldDecl)) {
      return ts.factory.createMethodDeclaration(
        mods,
        oldDecl.asteriskToken,
        ts.factory.createIdentifier(name),
        oldDecl.questionToken,
        oldDecl.typeParameters,
        oldDecl.parameters,
        oldDecl.type,
        oldDecl.body
      );
    } else if (ts.isGetAccessorDeclaration(oldDecl)) {
      return ts.factory.createGetAccessorDeclaration(
        mods,
        ts.factory.createIdentifier(name),
        oldDecl.parameters,
        oldDecl.type,
        oldDecl.body
      );
    }
    return ts.factory.createSetAccessorDeclaration(
      mods,
      ts.factory.createIdentifier(name),
      oldDecl.parameters,
      oldDecl.body
    );
  }

  fixRecordObjectLiteral(objectLiteralExpr: ts.ObjectLiteralExpression): Autofix[] | undefined {
    const autofix: Autofix[] = [];

    for (const prop of objectLiteralExpr.properties) {
      if (!prop.name) {
        return undefined;
      }
      if (this.utils.isValidRecordObjectLiteralKey(prop.name)) {
        // Skip property with a valid property key.
        continue;
      }
      if (!ts.isIdentifier(prop.name)) {
        // Can only fix identifier name.
        return undefined;
      }

      const stringLiteralName = ts.factory.createStringLiteralFromNode(prop.name, true);
      const text = this.printer.printNode(ts.EmitHint.Unspecified, stringLiteralName, prop.name.getSourceFile());
      autofix.push({ start: prop.name.getStart(), end: prop.name.getEnd(), replacementText: text });
    }

    return autofix;
  }

  fixUntypedObjectLiteral(
    objectLiteralExpr: ts.ObjectLiteralExpression,
    objectLiteralType: ts.Type | undefined
  ): Autofix[] | undefined {
    if (objectLiteralType) {

      /*
       * Special case for object literal of Record type: fix object's property names
       * by replacing identifiers with string literals.
       */
      if (this.utils.isStdRecordType(this.utils.getNonNullableType(objectLiteralType))) {
        return this.fixRecordObjectLiteral(objectLiteralExpr);
      }

      // Can't fix when object literal has a contextual type.
      return undefined;
    }

    const enclosingStmt = TsUtils.getEnclosingTopLevelStatement(objectLiteralExpr);
    if (!enclosingStmt) {
      return undefined;
    }

    const newInterfaceProps = this.getInterfacePropertiesFromObjectLiteral(objectLiteralExpr, enclosingStmt);
    if (!newInterfaceProps) {
      return undefined;
    }

    const srcFile = objectLiteralExpr.getSourceFile();
    const newInterfaceName = TsUtils.generateUniqueName(this.objectLiteralInterfaceNameGenerator, srcFile);
    if (!newInterfaceName) {
      return undefined;
    }

    return [
      this.createNewInterface(srcFile, newInterfaceName, newInterfaceProps, enclosingStmt.getStart()),
      this.fixObjectLiteralExpression(srcFile, newInterfaceName, objectLiteralExpr)
    ];
  }

  private getInterfacePropertiesFromObjectLiteral(
    objectLiteralExpr: ts.ObjectLiteralExpression,
    enclosingStmt: ts.Node
  ): ts.PropertySignature[] | undefined {
    const interfaceProps: ts.PropertySignature[] = [];
    for (const prop of objectLiteralExpr.properties) {
      const interfaceProp = this.getInterfacePropertyFromObjectLiteralElement(prop, enclosingStmt);
      if (!interfaceProp) {
        return undefined;
      }
      interfaceProps.push(interfaceProp);
    }
    return interfaceProps;
  }

  private getInterfacePropertyFromObjectLiteralElement(
    prop: ts.ObjectLiteralElementLike,
    enclosingStmt: ts.Node
  ): ts.PropertySignature | undefined {
    // Can't fix if property is not a key-value pair, or the property name is a computed value.
    if (!ts.isPropertyAssignment(prop) || ts.isComputedPropertyName(prop.name)) {
      return undefined;
    }

    const propType = this.typeChecker.getTypeAtLocation(prop);

    // Can't capture generic type parameters of enclosing declarations.
    if (this.utils.hasGenericTypeParameter(propType)) {
      return undefined;
    }

    if (Autofixer.propertyTypeIsCapturedFromEnclosingLocalScope(propType, enclosingStmt)) {
      return undefined;
    }

    const propTypeNode = this.typeChecker.typeToTypeNode(propType, undefined, ts.NodeBuilderFlags.None);
    if (!propTypeNode || !this.utils.isSupportedType(propTypeNode)) {
      return undefined;
    }

    const newProp: ts.PropertySignature = ts.factory.createPropertySignature(
      undefined,
      prop.name,
      undefined,
      propTypeNode
    );
    return newProp;
  }

  private static propertyTypeIsCapturedFromEnclosingLocalScope(type: ts.Type, enclosingStmt: ts.Node): boolean {
    const sym = type.getSymbol();
    let symNode: ts.Node | undefined = TsUtils.getDeclaration(sym);

    while (symNode) {
      if (symNode === enclosingStmt) {
        return true;
      }
      symNode = symNode.parent;
    }

    return false;
  }

  private createNewInterface(
    srcFile: ts.SourceFile,
    interfaceName: string,
    members: ts.TypeElement[],
    pos: number
  ): Autofix {
    const newInterfaceDecl = ts.factory.createInterfaceDeclaration(
      undefined,
      interfaceName,
      undefined,
      undefined,
      members
    );
    const text = this.printer.printNode(ts.EmitHint.Unspecified, newInterfaceDecl, srcFile) + '\n';
    return { start: pos, end: pos, replacementText: text };
  }

  private fixObjectLiteralExpression(
    srcFile: ts.SourceFile,
    newInterfaceName: string,
    objectLiteralExpr: ts.ObjectLiteralExpression
  ): Autofix {

    /*
     * If object literal is initializing a variable or property,
     * then simply add new 'contextual' type to the declaration.
     * Otherwise, cast object literal to newly created interface type.
     */
    if (
      (ts.isVariableDeclaration(objectLiteralExpr.parent) ||
        ts.isPropertyDeclaration(objectLiteralExpr.parent) ||
        ts.isParameter(objectLiteralExpr.parent)) &&
      !objectLiteralExpr.parent.type
    ) {
      const text = ': ' + newInterfaceName;
      const pos = Autofixer.getDeclarationTypePositionForObjectLiteral(objectLiteralExpr.parent);
      return { start: pos, end: pos, replacementText: text };
    }

    const newTypeRef = ts.factory.createTypeReferenceNode(newInterfaceName);
    let newExpr: ts.Expression = ts.factory.createAsExpression(
      ts.factory.createObjectLiteralExpression(objectLiteralExpr.properties),
      newTypeRef
    );
    if (!ts.isParenthesizedExpression(objectLiteralExpr.parent)) {
      newExpr = ts.factory.createParenthesizedExpression(newExpr);
    }
    const text = this.printer.printNode(ts.EmitHint.Unspecified, newExpr, srcFile);
    return { start: objectLiteralExpr.getStart(), end: objectLiteralExpr.getEnd(), replacementText: text };
  }

  private static getDeclarationTypePositionForObjectLiteral(
    decl: ts.VariableDeclaration | ts.PropertyDeclaration | ts.ParameterDeclaration
  ): number {
    if (ts.isPropertyDeclaration(decl)) {
      return (decl.questionToken || decl.exclamationToken || decl.name).getEnd();
    } else if (ts.isParameter(decl)) {
      return (decl.questionToken || decl.name).getEnd();
    }
    return (decl.exclamationToken || decl.name).getEnd();
  }

  private readonly objectLiteralInterfaceNameGenerator = new NameGenerator(
    GENERATED_OBJECT_LITERAL_INTERFACE_NAME,
    GENERATED_OBJECT_LITERAL_INTERFACE_TRESHOLD
  );

  /*
   * In case of type alias initialized with type literal, replace
   * entire type alias with identical interface declaration.
   */
  private proceedTypeAliasDeclaration(typeLiteral: ts.TypeLiteralNode): Autofix[] | undefined {
    if (ts.isTypeAliasDeclaration(typeLiteral.parent)) {
      const typeAlias = typeLiteral.parent;
      const newInterfaceDecl = ts.factory.createInterfaceDeclaration(
        typeAlias.modifiers,
        typeAlias.name,
        typeAlias.typeParameters,
        undefined,
        typeLiteral.members
      );
      const text = this.printer.printNode(ts.EmitHint.Unspecified, newInterfaceDecl, typeLiteral.getSourceFile());
      return [{ start: typeAlias.getStart(), end: typeAlias.getEnd(), replacementText: text }];
    }
    return undefined;
  }

  fixTypeliteral(typeLiteral: ts.TypeLiteralNode): Autofix[] | undefined {
    const typeAliasAutofix = this.proceedTypeAliasDeclaration(typeLiteral);
    if (typeAliasAutofix) {
      return typeAliasAutofix;
    }

    /*
     * Create new interface declaration with members of type literal
     * and put the interface name in place of the type literal.
     */
    const srcFile = typeLiteral.getSourceFile();
    const enclosingStmt = TsUtils.getEnclosingTopLevelStatement(typeLiteral);
    if (!enclosingStmt) {
      return undefined;
    }

    if (this.typeLiteralCapturesTypeFromEnclosingLocalScope(typeLiteral, enclosingStmt)) {
      return undefined;
    }

    const newInterfaceName = TsUtils.generateUniqueName(this.typeLiteralInterfaceNameGenerator, srcFile);
    if (!newInterfaceName) {
      return undefined;
    }
    const newInterfacePos = enclosingStmt.getStart();
    const newInterfaceDecl = ts.factory.createInterfaceDeclaration(
      undefined,
      newInterfaceName,
      undefined,
      undefined,
      typeLiteral.members
    );
    const interfaceText = this.printer.printNode(ts.EmitHint.Unspecified, newInterfaceDecl, srcFile) + '\n';

    return [
      { start: newInterfacePos, end: newInterfacePos, replacementText: interfaceText },
      { start: typeLiteral.getStart(), end: typeLiteral.getEnd(), replacementText: newInterfaceName }
    ];
  }

  typeLiteralCapturesTypeFromEnclosingLocalScope(typeLiteral: ts.TypeLiteralNode, enclosingStmt: ts.Node): boolean {
    let found = false;

    const callback = (node: ts.Node): void => {
      if (!ts.isIdentifier(node)) {
        return;
      }
      const sym = this.typeChecker.getSymbolAtLocation(node);
      let symNode: ts.Node | undefined = TsUtils.getDeclaration(sym);
      while (symNode) {
        if (symNode === typeLiteral) {
          return;
        }
        if (symNode === enclosingStmt) {
          found = true;
          return;
        }
        symNode = symNode.parent;
      }
    };

    const stopCondition = (node: ts.Node): boolean => {
      void node;
      return found;
    };

    forEachNodeInSubtree(typeLiteral, callback, stopCondition);
    return found;
  }

  // eslint-disable-next-line class-methods-use-this
  removeDecorator(decorator: ts.Decorator): Autofix[] {
    return [{ start: decorator.getStart(), end: decorator.getEnd(), replacementText: '' }];
  }

  private readonly typeLiteralInterfaceNameGenerator = new NameGenerator(
    GENERATED_TYPE_LITERAL_INTERFACE_NAME,
    GENERATED_TYPE_LITERAL_INTERFACE_TRESHOLD
  );

  private readonly destructObjNameGenerator = new NameGenerator(
    GENERATED_DESTRUCT_OBJECT_NAME,
    GENERATED_DESTRUCT_OBJECT_TRESHOLD
  );

  private readonly destructArrayNameGenerator = new NameGenerator(
    GENERATED_DESTRUCT_ARRAY_NAME,
    GENERATED_DESTRUCT_ARRAY_TRESHOLD
  );

  private readonly symbolCache: SymbolCache;
}
