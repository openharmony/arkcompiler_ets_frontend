/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
  forEachChild,
  getModifiers,
  isCatchClause,
  isClassDeclaration,
  isConstructorDeclaration,
  isFunctionDeclaration,
  isFunctionLike,
  isIdentifier,
  isMethodDeclaration,
  SyntaxKind,
  isVariableDeclaration,
  isFunctionExpression,
  isArrowFunction,
  isGetAccessor,
  isSetAccessor,
  isPropertyDeclaration,
  getOriginalNode
} from 'typescript';

import type {
  BreakOrContinueStatement,
  CaseBlock,
  CatchClause,
  ClassDeclaration,
  ClassElement,
  ClassExpression,
  EnumDeclaration,
  ExportSpecifier,
  ForInOrOfStatement,
  ForStatement,
  FunctionLikeDeclaration,
  Identifier,
  ImportEqualsDeclaration,
  ImportSpecifier,
  InterfaceDeclaration,
  LabeledStatement,
  ModuleDeclaration,
  NamespaceExport,
  Node,
  ObjectBindingPattern,
  ObjectLiteralExpression,
  ParameterDeclaration,
  SourceFile,
  Symbol,
  SymbolTable,
  TypeAliasDeclaration,
  TypeChecker,
  TypeElement
} from 'typescript';

import {NodeUtils} from './NodeUtils';
import {isParameterPropertyModifier, isViewPUBasedClass} from './OhsUtil';
/**
 * kind of a scope
 */
namespace secharmony {
  type ForLikeStatement = ForStatement | ForInOrOfStatement;
  type ClassLikeDeclaration = ClassDeclaration | ClassExpression;
  export const noSymbolIdentifier: Set<string> = new Set();

  /**
   * type of scope
   */
  export enum ScopeKind {
    GLOBAL,
    MODULE,
    FUNCTION,
    CLASS,
    FOR,
    SWITCH,
    BLOCK,
    INTERFACE,
    CATCH,
    ENUM,
    OBJECT_LITERAL
  }

  export function isGlobalScope(scope: Scope): boolean {
    return scope.kind === ScopeKind.GLOBAL;
  }

  export function isFunctionScope(scope: Scope): boolean {
    return scope.kind === ScopeKind.FUNCTION;
  }

  export function isClassScope(scope: Scope): boolean {
    return scope.kind === ScopeKind.CLASS;
  }

  export function isInterfaceScope(scope: Scope): boolean {
    return scope.kind === ScopeKind.INTERFACE;
  }

  export function isEnumScope(scope: Scope): boolean {
    return scope.kind === ScopeKind.ENUM;
  }

  export function isObjectLiteralScope(scope: Scope): boolean {
    return scope.kind === ScopeKind.OBJECT_LITERAL;
  }

  /**
   * get a new scope.
   * @param name - name of the scope.
   * @param node - node of a current scope in ast.
   * @param type - type of the scope.
   * @param lexicalScope - indicates if the scope is a lexical scope.
   * @param upper - parent scope of the current scope.
   */
  export class Scope {
    // scope name
    name: string;
    // kind of a scope, such as global ,function like, block ..
    kind: ScopeKind;
    // node of a current scope in ast.
    block: Node;
    // parent scope of current scope
    parent: Scope | undefined;
    // sub scopes of current scope
    children: Scope[];

    // symbols define in current scope
    defs: Set<Symbol>;

    // labels in current scope
    labels: Label[];

    importNames: Set<string>;
    exportNames: Set<string>;
    fileExportNames?: Set<string>;
    fileImportNames?: Set<string>;
    mangledNames: Set<string>;
    // location path
    loc: string;

    constructor(name: string, node: Node, type: ScopeKind, lexicalScope: boolean = false, upper?: Scope) {
      this.name = name;
      this.kind = type;
      this.block = node;
      this.parent = upper;
      this.children = [];
      this.defs = new Set<Symbol>();
      this.labels = [];
      this.importNames = new Set<string>();
      this.exportNames = new Set<string>();
      this.mangledNames = new Set<string>();
      this.loc = this.parent?.loc ? this.parent.loc + '#' + this.name : this.name;

      this.parent?.addChild(this);
    }

    /**
     * add a sub scope to current scope
     *
     * @param child
     */
    addChild(child: Scope): void {
      this.children.push(child);
    }

    /**
     * add definition symbol into current scope
     *
     * @param def definition symbol
     */
    addDefinition(def: Symbol, obfuscateAsProperty: boolean = false): void {
      if (this.kind === ScopeKind.GLOBAL || obfuscateAsProperty) {
        Reflect.set(def, 'obfuscateAsProperty', true);
      }
      this.defs.add(def);
    }

    /**
     * add label to current scope
     *
     * @param label label statement
     */
    addLabel(label: Label): void {
      this.labels.push(label);
    }

    /**
     * get symbol location
     *
     * @param sym symbol
     */
    getSymbolLocation(sym: Symbol): string {
      if (!this.defs.has(sym)) {
        return '';
      }

      return this.loc ? sym.name : this.loc + '#' + sym.name;
    }

    /**
     * get label location
     *
     * @param label
     */
    getLabelLocation(label: Label): string {
      if (!this.labels.includes(label)) {
        return '';
      }

      let index: number = this.labels.findIndex((lb: Label) => lb === label);
      return this.loc ? label.name : this.loc + '#' + index + label.name;
    }
  }

  export interface Label {
    name: string;
    locInfo: string;
    refs: Identifier[];
    parent: Label | undefined;
    children: Label[];
    scope: Scope;
  }

  export function createLabel(node: LabeledStatement, scope: Scope, parent?: Label | undefined): Label {
    let labelName: string = '$' + scope.labels.length + '_' + node.label.text;
    let label: Label = {
      'name': node.label.text,
      'locInfo': labelName,
      'refs': [node.label],
      'parent': parent,
      'children': [],
      'scope': scope,
    };

    scope.labels.push(label);
    parent?.children.push(label);

    return label;
  }

  export interface ScopeManager {

    /**
     * get reserved names like ViewPU component class name
     */
    getReservedNames(): Set<string>;

    /**
     * do scope analysis
     *
     * @param ast ast tree of a source file
     * @param checker
     */
    analyze(ast: SourceFile, checker: TypeChecker, isEnabledExportObfuscation: boolean): void;

    /**
     * get root scope of a file
     */
    getRootScope(): Scope;

    /**
     * find block Scope of a node
     * @param node
     */
    getScopeOfNode(node: Node): Scope | undefined;
  }

  export function createScopeManager(): ScopeManager {
    let reservedNames: Set<string> = new Set<string>();
    let root: Scope;
    let current: Scope;
    let scopes: Scope[] = [];

    let checker: TypeChecker = null;
    let upperLabel: Label | undefined = undefined;
    let exportObfuscation: boolean = false;

    return {
      getReservedNames,
      analyze,
      getRootScope,
      getScopeOfNode,
    };

    function analyze(ast: SourceFile, typeChecker: TypeChecker, isEnabledExportObfuscation = false): void {
      checker = typeChecker;
      exportObfuscation = isEnabledExportObfuscation;
      analyzeScope(ast);
    }

    function getReservedNames(): Set<string> {
      return reservedNames;
    }

    function getRootScope(): Scope {
      return root;
    }

    function addSymbolInScope(node: Node): void {
      let defSymbols: SymbolTable = node?.locals;
      if (!defSymbols) {
        return;
      }

      defSymbols.forEach((def: Symbol) => {
        // with export identification, special handling.
        if (def.exportSymbol) {
          current.exportNames.add(def.name);
          root.fileExportNames.add(def.name);
          if (def.exportSymbol.name === def.name) {
            /* For export declaration, `def` and its `exportSymbol` has same name,
                eg. export class Ability {}
                  def.name: "Ability"
                  def.exportSymbol.name: "Ability"
                Collect the `def.exportSymbol` since import symbol is asscociated with it.
            */
            current.addDefinition(def.exportSymbol, true);
          } else {
            /* For default exports, `def` and its `exportSymbol` has different name,
                eg. export default class Ability {}
                  def.name: "Ability"
                  def.exportSymbol.name: "default"
              Collect the `def` symbol since we should obfuscate "Ability" instead of "default".
            */
            current.addDefinition(def);
          }
        } else {
          current.addDefinition(def);
        }
      });
    }

    function addExportSymbolInScope(node: Node): void {
      let defSymbols: Symbol = node?.symbol;

      if (!defSymbols) {
        return;
      }
      current.addDefinition(defSymbols);
    }

    /**
     * analyze chain of scopes
     * @param node
     */
    function analyzeScope(node: Node): void {
      switch (node.kind) {
        // global
        case SyntaxKind.SourceFile:
          analyzeSourceFile(node as SourceFile);
          break;

        // namespace or module
        case SyntaxKind.ModuleDeclaration:
          analyzeModule(node as ModuleDeclaration);
          break;

        // function like
        case SyntaxKind.FunctionDeclaration:
        case SyntaxKind.MethodDeclaration:
        case SyntaxKind.GetAccessor:
        case SyntaxKind.SetAccessor:
        case SyntaxKind.Constructor:
        case SyntaxKind.FunctionExpression:
        case SyntaxKind.ArrowFunction:
          analyzeFunctionLike(node as FunctionLikeDeclaration);
          break;

        // class like
        case SyntaxKind.ClassExpression:
        case SyntaxKind.ClassDeclaration:
        case SyntaxKind.StructDeclaration:
          analyzeClassLike(node as ClassLikeDeclaration);
          break;

        // for like
        case SyntaxKind.ForStatement:
        case SyntaxKind.ForInStatement:
        case SyntaxKind.ForOfStatement:
          analyzeForLike(node as ForLikeStatement);
          break;
        case SyntaxKind.CaseBlock:
          // caseBlock property in switch statement
          analyzeSwitch(node as CaseBlock);
          break;
        case SyntaxKind.Block:
          // while, do ...while, block, if/else..
          analyzeBlock(node);
          break;

        case SyntaxKind.InterfaceDeclaration:
          analyzeInterface(node as InterfaceDeclaration);
          break;

        case SyntaxKind.EnumDeclaration:
          analyzeEnum(node as EnumDeclaration);
          break;

        case SyntaxKind.Identifier:
          analyzeSymbol(node as Identifier);
          break;

        case SyntaxKind.TypeAliasDeclaration:
          analyzeTypeAliasDeclaration(node as TypeAliasDeclaration);
          break;

        case SyntaxKind.LabeledStatement:
          analyzeLabel(node as LabeledStatement);
          break;

        case SyntaxKind.BreakStatement:
        case SyntaxKind.ContinueStatement:
          analyzeBreakOrContinue(node as BreakOrContinueStatement);
          break;
        case SyntaxKind.ImportSpecifier:
          analyzeImportNames(node as ImportSpecifier);
          break;

        case SyntaxKind.ObjectBindingPattern:
          analyzeObjectBindingPatternRequire(node as ObjectBindingPattern);
          break;

        case SyntaxKind.ObjectLiteralExpression:
          analyzeObjectLiteralExpression(node as ObjectLiteralExpression);
          break;

        case SyntaxKind.ExportSpecifier:
          analyzeExportNames(node as ExportSpecifier);
          break;

        case SyntaxKind.NamespaceExport:
          analyzeNamespaceExport(node as NamespaceExport);
          break;

        case SyntaxKind.CatchClause:
          analyzeCatchClause(node as CatchClause);
          break;

        case SyntaxKind.ImportEqualsDeclaration:
          analyzeImportEqualsDeclaration(node as ImportEqualsDeclaration);
          break;

        default:
          forEachChild(node, analyzeScope);
          break;
      }
    }

    function analyzeImportNames(node: ImportSpecifier): void {
      try {
        const propetyNameNode: Identifier | undefined = node.propertyName;
        if (exportObfuscation && propetyNameNode && isIdentifier(propetyNameNode)) {
          let propertySymbol = checker.getSymbolAtLocation(propetyNameNode);
          if (!propertySymbol) {
            noSymbolIdentifier.add(propetyNameNode.text);
          } else {
            current.addDefinition(propertySymbol);
          }

          const nameSymbol = checker.getSymbolAtLocation(node.name);
          if (nameSymbol) {
            current.addDefinition(nameSymbol);
          }
        } else {
          const nameText = propetyNameNode ? propetyNameNode.text : node.name.text;
          current.importNames.add(nameText);
          root.fileImportNames.add(nameText);
        }
        forEachChild(node, analyzeScope);
      } catch (e) {
        console.error(e);
      }
    }

    /** example
     * const { x1, y: customY, z = 0 }: { x: number; y?: number; z?: number } = { x: 1, y: 2 };
     * bindingElement.name is x1 for the first element.
     * bindingElement.name is customY for the second element.
     */
    function analyzeObjectBindingPatternRequire(node: ObjectBindingPattern): void {
      if (!NodeUtils.isObjectBindingPatternAssignment(node)) {
        forEachChild(node, analyzeScope);
        return;
      }

      if (!node.elements) {
        return;
      }

      node.elements.forEach((bindingElement) => {
        if (!bindingElement) {
          return;
        }

        findNoSymbolIdentifiers(bindingElement);

        if (!bindingElement.name || !isIdentifier(bindingElement.name)) {
          return;
        }

        if (bindingElement.propertyName) {
          return;
        }

        current.importNames.add(bindingElement.name.text);
        root.fileImportNames.add(bindingElement.name.text);
      });
    }

    function analyzeObjectLiteralExpression(node: ObjectLiteralExpression): void {
      let scopeName: string = '$' + current.children.length;
      current = new Scope(scopeName, node, ScopeKind.OBJECT_LITERAL, false, current);
      scopes.push(current);

      addSymbolInScope(node);
      forEachChild(node, analyzeScope);
      current = current.parent || current;
    }

    function analyzeExportNames(node: ExportSpecifier): void {
      // get export names.
      current.exportNames.add(node.name.text);
      root.fileExportNames.add(node.name.text);
      addExportSymbolInScope(node);
      const propetyNameNode: Identifier | undefined = node.propertyName;
      if (exportObfuscation && propetyNameNode && isIdentifier(propetyNameNode)) {
        let propertySymbol = checker.getSymbolAtLocation(propetyNameNode);
        if (!propertySymbol) {
          noSymbolIdentifier.add(propetyNameNode.text);
        }
      }
      forEachChild(node, analyzeScope);
    }

    function analyzeNamespaceExport(node: NamespaceExport): void {
      if (!exportObfuscation) {
        return;
      }

      let symbol = checker.getSymbolAtLocation(node.name);
      if (symbol) {
        current.addDefinition(symbol, true);
      }
    }

    function analyzeBreakOrContinue(node: BreakOrContinueStatement): void {
      let labelName: string = node?.label?.text ?? '';
      let label: Label = findTargetLabel(labelName);
      if (!label) {
        return;
      }

      if (node.label) {
        label?.refs.push(node.label);
      }

      forEachChild(node, analyzeScope);
    }

    function findTargetLabel(labelName: string): Label | null {
      if (!labelName) {
        return null;
      }

      let label: Label | undefined = upperLabel;
      // avoid loop
      while (label && label?.name !== labelName) {
        label = label?.parent;
      }

      return label;
    }

    function analyzeSourceFile(node: SourceFile): void {
      let scopeName: string = '';
      root = new Scope(scopeName, node, ScopeKind.GLOBAL, true);
      root.fileExportNames = new Set<string>();
      root.fileImportNames = new Set<string>();
      current = root;
      scopes.push(current);
      // locals of a node(scope) is symbol that defines in current scope(node).
      addSymbolInScope(node);
      forEachChild(node, analyzeScope);
      current = current.parent || current;
      extractImportExports();
    }

    function analyzeCatchClause(node: CatchClause): void {
      let scopeName: string = '$' + current.children.length;
      current = new Scope(scopeName, node, ScopeKind.CATCH, false, current);
      scopes.push(current);
      // add in catch declaration.
      addSymbolInScope(node);
      if (node.block) {
        // add in block declaration.
        addSymbolInScope(node.block);
      }

      forEachChild(node, analyzeScope);
      current = current.parent || current;
    }

    function extractImportExports(): void {
      for (const def of current.defs) {
        if (def.exportSymbol) {
          if (!current.exportNames.has(def.name)) {
            current.exportNames.add(def.name);
            root.fileExportNames.add(def.name);
          }
          const name: string = def.exportSymbol.name;
          if (!current.exportNames.has(name)) {
            current.exportNames.add(name);
            root.fileExportNames.add(def.name);
          }
        }
      }
    }

    function analyzeTypeAliasDeclaration(node: TypeAliasDeclaration): void {
      let scopeName: string = node.name.text ?? '$' + current.children.length;
      current = new Scope(scopeName, node, ScopeKind.INTERFACE, true, current);
      scopes.push(current);
      addSymbolInScope(node);
      forEachChild(node, analyzeScope);
      current = current.parent || current;
    }

    /**
     * namespace ns {
     *     ...
     * }
     * @param node
     */
    function analyzeModule(node: ModuleDeclaration): void {
      /**
       * if it is an anonymous scope, generate the scope name with a number,
       * which is based on the order of its child scopes in the upper scope
       */
      let scopeName: string = node.name.text ?? '$' + current.children.length;
      current = new Scope(scopeName, node, ScopeKind.MODULE, true, current);
      scopes.push(current);
      addSymbolInScope(node);
      node.forEachChild((sub: Node) => {
        if (isIdentifier(sub)) {
          return;
        }
        analyzeScope(sub);
      });
      current = current.parent || current;
    }

    /**
     * exclude constructor's parameter witch should be treated as property, example:
     *  constructor(public name){}, name should be treated as property
     * @param node
     */
    function excludeConstructorParameter(node: Node): void {
      if (!isConstructorDeclaration(node)) {
        return;
      }

      const visitParam = (param: ParameterDeclaration): void => {
        const modifiers = getModifiers(param);
        if (!modifiers || modifiers.length <= 0) {
          return;
        }

        const findRet = modifiers.find(modifier => isParameterPropertyModifier(modifier));
        if (!isIdentifier(param.name) || findRet === undefined) {
          return;
        }

        current.defs.forEach((def) => {
          if (isIdentifier(param.name) && (def.name === param.name.text)) {
            current.defs.delete(def);
            current.mangledNames.add(def.name);
          }
        });
      };

      node.parameters.forEach((param) => {
        visitParam(param);
      });
    }

    /**
     * function func(param1...) {
     *     ...
     * }
     * @param node
     */
    function analyzeFunctionLike(node: FunctionLikeDeclaration): void {
      // For example, the constructor of the StructDeclaration, inserted by arkui, will add a virtual attribute.
      // @ts-ignore
      if (getOriginalNode(node).virtual) {
        return;
      }
      let scopeName: string = (node?.name as Identifier)?.text ?? '$' + current.children.length;
      let loc: string = current?.loc ? current.loc + '#' + scopeName : scopeName;
      let overloading: boolean = false;
      for (const sub of current.children) {
        if (sub.loc === loc) {
          overloading = true;
          current = sub;
          break;
        }
      }

      if (!overloading) {
        current = new Scope(scopeName, node, ScopeKind.FUNCTION, true, current);
        scopes.push(current);
      }

      let symbol: Symbol;
      if ((isFunctionExpression(node) || isArrowFunction(node)) && isVariableDeclaration(node.parent)) {
        symbol = checker.getSymbolAtLocation(node.name ? node.name : node.parent.name);
      } else {
        if (isFunctionDeclaration(node)) {
          symbol = NodeUtils.findSymbolOfIdentifier(checker, node.name);
        } else {
          symbol = checker.getSymbolAtLocation(node.name);
        }
      }
      if (symbol) {
        Reflect.set(symbol, 'isFunction', true);
      }

      addSymbolInScope(node);
      /**
       * {
       *   get name(): "INT";
       *   set orignal(): 0;
       * }
       * // the above getaccessor and setaccessor were obfuscated as identifiers.
       */
      if (!(isGetAccessor(node) || isSetAccessor(node)) && symbol && current.parent && !current.parent.defs.has(symbol)) {
        /*
          Handle the case when `FunctionLikeDeclaration` node is as initializer of variable declaration.
          eg. const foo = function bar() {};
          The `current` scope is the function's scope, the `current.parent` scope is where the function is defined.
          `foo` has already added in the parent scope, we need to add `bar` here too.
         */
        current.parent.defs.add(symbol);
      }

      if (isFunctionDeclaration(node) || isMethodDeclaration(node)) {
        // function declaration requires skipping function names
        node.forEachChild((sub: Node) => {
          if (isIdentifier(sub)) {
            tryAddNoSymbolIdentifiers(sub);
            return;
          }

          analyzeScope(sub);
        });
      } else {
        forEachChild(node, analyzeScope);
      }

      excludeConstructorParameter(node);
      current = current.parent || current;
    }

    function analyzeSwitch(node: CaseBlock): void {
      let scopeName: string = '$' + current.children.length;
      current = new Scope(scopeName, node, ScopeKind.SWITCH, false, current);
      scopes.push(current);
      addSymbolInScope(node);
      forEachChild(node, analyzeScope);
      current = current.parent || current;
    }

    /**
     * ES6+ class like scope, The members of a class aren't not allow to rename in rename identifiers transformer, but
     * rename in rename properties transformer.
     *
     * @param node
     */
    function analyzeClassLike(node: ClassLikeDeclaration): void {
      if (isClassDeclaration(node) && isViewPUBasedClass(node)) {
        reservedNames.add(node.name.text);
      }

      try {
        let scopeName: string = node?.name?.text ?? '$' + current.children.length;
        current = new Scope(scopeName, node, ScopeKind.CLASS, true, current);
        scopes.push(current);
        addSymbolInScope(node);
        // Class members are seen as attribute names, and  the reference of external symbols can be renamed as the same
        node.members?.forEach((elm: ClassElement) => {
          // @ts-ignore
          if (elm?.symbol && !getOriginalNode(elm).virtual) {
            current.addDefinition(elm.symbol);
          }
        });

        forEachChild(node, analyzeScope);
      } catch (e) {
        console.error(e);
      }

      current = current.parent || current;
    }

    function analyzeForLike(node: ForLikeStatement): void {
      let scopeName: string = '$' + current.children.length;
      current = new Scope(scopeName, node, ScopeKind.FOR, false, current);
      scopes.push(current);
      addSymbolInScope(node);
      forEachChild(node, analyzeScope);
      current = current.parent || current;
    }

    function analyzeBlock(node: Node): void {
      // when block is body of a function
      if ((isFunctionScope(current) && isFunctionLike(node.parent)) || isCatchClause(node.parent)) {
        // skip direct block scope in function scope
        forEachChild(node, analyzeScope);
        return;
      }

      let scopeName: string = '$' + current.children.length;
      current = new Scope(scopeName, node, ScopeKind.BLOCK, false, current);
      scopes.push(current);
      addSymbolInScope(node);
      forEachChild(node, analyzeScope);
      current = current.parent || current;
    }

    function analyzeInterface(node: InterfaceDeclaration): void {
      let scopeName: string = node.name.text;
      current = new Scope(scopeName, node, ScopeKind.INTERFACE, true, current);
      scopes.push(current);
      try {
        addSymbolInScope(node);
      } catch (e) {
        console.error('');
      }

      node.members?.forEach((elm: TypeElement) => {
        if (elm?.symbol) {
          current.addDefinition(elm.symbol);
        }
      });

      forEachChild(node, analyzeScope);
      current = current.parent || current;
    }

    function analyzeEnum(node: EnumDeclaration): void {
      let scopeName: string = node.name.text;
      current = new Scope(scopeName, node, ScopeKind.ENUM, true, current);
      scopes.push(current);
      for (const member of node.members) {
        if (member.symbol) {
          current.addDefinition(member.symbol);
        }
      }

      forEachChild(node, analyzeScope);
      current = current.parent || current;
    }

    function analyzeSymbol(node: Identifier): void {
      // ignore all identifiers that treat as property in property access
      if (NodeUtils.isPropertyAccessNode(node)) {
        return;
      }

      let symbol: Symbol = null;

      try {
        symbol = NodeUtils.findSymbolOfIdentifier(checker, node);
      } catch (e) {
        console.error(e);
        return;
      }

      if (!symbol) {
        current.mangledNames.add(node.text);
        return;
      }

      // ignore all identifiers that treat as property in property declaration
      if (NodeUtils.isPropertyDeclarationNode(node)) {
        return;
      }

      // add def symbol that don't found in current defs.
      addSymbolIntoDefsIfNeeded(node, symbol, current.defs);
    }

    function addSymbolIntoDefsIfNeeded(node: Identifier, symbol: Symbol, currentDefs: Set<Symbol>): boolean {
      // process a new def not in currentDefs
      let isSameName: boolean = false;
      for (const def of currentDefs) {
        if (def.name === node.text) {
          isSameName = true;
          break;
        }
      }

      if (isSameName) {
        // exclude the possibility of external symbols, as those with duplicate names have been added to currentDefs (this avoids the possibility of omissions)
        if (!currentDefs.has(symbol)) {
          currentDefs.add(symbol);
        }

        if (symbol.exportSymbol && !currentDefs.has(symbol.exportSymbol)) {
          Reflect.set(symbol, 'obfuscateAsProperty', true);
          currentDefs.add(symbol);
        }
      }

      return isSameName;
    }

    function analyzeLabel(node: LabeledStatement): void {
      // labels within the same scope are allowed to be duplicated, so label names need to have numbering information to distinguish them
      upperLabel = upperLabel ? createLabel(node, current, upperLabel) : createLabel(node, current);
      forEachChild(node, analyzeScope);
      upperLabel = upperLabel?.parent;
    }

    function getScopeOfNode(node: Node): Scope | undefined {
      if (!isIdentifier(node)) {
        return undefined;
      }

      let sym: Symbol = checker.getSymbolAtLocation(node);
      if (!sym) {
        return undefined;
      }

      for (const scope of scopes) {
        if (scope?.defs.has(sym)) {
          return scope;
        }
      }

      return undefined;
    }

    function analyzeImportEqualsDeclaration(node: ImportEqualsDeclaration): void {
      let hasExport: boolean = false;
      if (node.modifiers) {
        for (const modifier of node.modifiers) {
          if (modifier.kind === SyntaxKind.ExportKeyword) {
            hasExport = true;
            break;
          }
        }
      }
      if (hasExport) {
        current.exportNames.add(node.name.text);
        root.fileExportNames.add(node.name.text);
        let sym: Symbol | undefined = checker.getSymbolAtLocation(node.name);
        if (sym) {
          current.addDefinition(sym, true);
        }
      }
      forEachChild(node, analyzeScope);
    }

    function tryAddNoSymbolIdentifiers(node: Identifier): void {
      if (!isIdentifier(node)) {
        return;
      }

      // skip property in property access expression
      if (NodeUtils.isPropertyAccessNode(node)) {
        return;
      }

      const sym: Symbol | undefined = checker.getSymbolAtLocation(node);
      if (!sym) {
        current.mangledNames.add((node as Identifier).text);
      }
    }

    function findNoSymbolIdentifiers(node: Node): void {
      const noSymbolVisit = (targetNode: Node): void => {
        if (!isIdentifier(targetNode)) {
          forEachChild(targetNode, noSymbolVisit);
          return;
        }
        tryAddNoSymbolIdentifiers(targetNode);
      };

      noSymbolVisit(node);
    }
  }
}

export = secharmony;
