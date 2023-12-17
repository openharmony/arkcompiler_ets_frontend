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
  forEachChild,
  isBreakOrContinueStatement,
  isConstructorDeclaration,
  isExportSpecifier,
  isIdentifier,
  isImportSpecifier,
  isLabeledStatement,
  isSourceFile,
  isStructDeclaration,
  setParentRecursive,
  visitEachChild,
} from 'typescript';

import type {
  ClassElement,
  Identifier,
  Node,
  SourceFile,
  StructDeclaration,
  Symbol,
  TransformationContext,
  Transformer,
  TransformerFactory,
  TypeChecker
} from 'typescript';

import {
  createScopeManager,
  isClassScope,
  isGlobalScope,
  isEnumScope,
  isInterfaceScope,
  isObjectLiteralScope,
  noSymbolIdentifier,
} from '../../utils/ScopeAnalyzer';

import type {
  Label,
  Scope,
  ScopeManager
} from '../../utils/ScopeAnalyzer';

import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import type {IOptions} from '../../configs/IOptions';
import type {INameObfuscationOption} from '../../configs/INameObfuscationOption';
import type {TransformPlugin} from '../TransformPlugin';
import {TransformerOrder} from '../TransformPlugin';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';
import {TypeUtils} from '../../utils/TypeUtils';
import {collectIdentifiersAndStructs} from '../../utils/TransformUtil';
import {NodeUtils} from '../../utils/NodeUtils';
import {ApiExtractor} from '../../common/ApiExtractor';
import { globalMangledTable, historyMangledTable, reservedProperties } from './RenamePropertiesTransformer';

namespace secharmony {
  /**
   * Rename Identifiers, including:
   * 1. variable name
   * 2. function name
   * 3. label name
   * 4. class name/interface name/ label name
   * we need implement some features:
   * 1. rename identifiers
   * 2. store/restore name to/from nameCache file.
   * 3. do scope analysis for identifier obfuscations
   *
   * @param option
   */
  const createRenameIdentifierFactory = function (option: IOptions): TransformerFactory<Node> {
    const profile: INameObfuscationOption | undefined = option?.mNameObfuscation;
    if (!profile || !profile.mEnable) {
      return null;
    }

    let options: NameGeneratorOptions = {};
    if (profile.mNameGeneratorType === NameGeneratorType.HEX) {
      options.hexWithPrefixSuffix = true;
    }
    let generator: INameGenerator = getNameGenerator(profile.mNameGeneratorType, options);

    const openTopLevel: boolean = option?.mNameObfuscation?.mTopLevel;
    const exportObfuscation: boolean = option?.mExportObfuscation;
    return renameIdentifierFactory;

    function renameIdentifierFactory(context: TransformationContext): Transformer<Node> {
      let reservedNames: string[] = [...(profile?.mReservedNames ?? []), 'this', '__global'];
      profile?.mReservedToplevelNames?.forEach(item => reservedProperties.add(item));
      let mangledSymbolNames: Map<Symbol, string> = new Map<Symbol, string>();
      let mangledLabelNames: Map<Label, string> = new Map<Label, string>();
      noSymbolIdentifier.clear();

      let historyMangledNames: Set<string> = undefined;
      if (historyNameCache && historyNameCache.size > 0) {
        historyMangledNames = new Set<string>(Array.from(historyNameCache.values()));
      }

      let checker: TypeChecker = undefined;
      let manager: ScopeManager = createScopeManager();
      let shadowIdentifiers: Identifier[] = undefined;
      let shadowStructs: StructDeclaration[] = undefined;

      let identifierIndex: number = 0;
      let structIndex: number = 0;
      return renameTransformer;

      /**
       * Transformer to rename identifiers
       *
       * @param node ast node of a file.
       */
      function renameTransformer(node: Node): Node {
        if (!isSourceFile(node)) {
          return node;
        }

        const shadowSourceAst: SourceFile = TypeUtils.createNewSourceFile(node);
        checker = TypeUtils.createChecker(shadowSourceAst);
        manager.analyze(shadowSourceAst, checker, exportObfuscation);

        // the reservedNames of manager contain the struct name.
        if (!exportObfuscation) {
          manager.getReservedNames().forEach((name) => {
            reservedNames.push(name);
          });
        }

        if (nameCache === undefined) {
          nameCache = new Map<string, string>();
        }

        let root: Scope = manager.getRootScope();
        renameInScope(root);
        root = undefined;
        // collect all identifiers of shadow sourceFile
        const identifiersAndStructs = collectIdentifiersAndStructs(shadowSourceAst, context);
        shadowIdentifiers = identifiersAndStructs.shadowIdentifiers;
        shadowStructs = identifiersAndStructs.shadowStructs;

        let ret: Node = visit(node);
        ret = tryRemoveVirtualConstructor(ret);
        return setParentRecursive(ret, true);
      }

      /**
       * rename symbol table store in scopes...
       *
       * @param scope scope, such as global, module, function, block
       */
      function renameInScope(scope: Scope): void {
        // process labels in scope, the label can't rename as the name of top labels.
        renameLabelsInScope(scope);
        // process symbols in scope, exclude property name.
        renameNamesInScope(scope);

        let subScope = undefined;
        while (scope.children.length > 0) {
          subScope = scope.children.pop();
          renameInScope(subScope);
          subScope = undefined;
        }
      }

      function renameNamesInScope(scope: Scope): void {
        if (isExcludeScope(scope)) {
          return;
        }

        if (!exportObfuscation) {
          scope.defs.forEach((def) => {
            let parentScope = scope;
            while (parentScope) {
              if (parentScope.importNames && parentScope.importNames.has(def.name)) {
                scope.defs.delete(def);
                scope.mangledNames.add(def.name);
              }
              parentScope = parentScope.parent;
            }
          });
        }

        renames(scope, scope.defs, generator);
      }

      function renames(scope: Scope, defs: Set<Symbol>, generator: INameGenerator): void {
        defs.forEach((def) => {
          const original: string = def.name;
          let mangled: string = original;
          // No allow to rename reserved names.
          if ((!Reflect.has(def, 'obfuscateAsProperty') && reservedNames.includes(original)) ||
            (!exportObfuscation && scope.exportNames.has(def.name)) ||
            isSkippedGlobal(openTopLevel, scope)) {
            scope.mangledNames.add(mangled);
            return;
          }

          if (mangledSymbolNames.has(def)) {
            return;
          }

          const path: string = scope.loc + '#' + original;
          const historyName: string = historyNameCache?.get(path);

          if (historyName) {
            mangled = historyName;
          } else if (Reflect.has(def, 'obfuscateAsProperty')) {
            mangled = getPropertyMangledName(original);
          } else {
            mangled = getMangled(scope, generator);
          }

          // add new names to name cache
          nameCache.set(path, mangled);
          scope.mangledNames.add(mangled);
          mangledSymbolNames.set(def, mangled);
        });
      }

      function getPropertyMangledName(original: string): string {
        if (reservedProperties.has(original)) {
          return original;
        }

        const historyName: string = historyMangledTable?.get(original);
        let mangledName: string = historyName ? historyName : globalMangledTable.get(original);

        while (!mangledName) {
          let tmpName = generator.getName();
          if (reservedProperties.has(tmpName) || tmpName === original) {
            continue;
          }

          let isInGlobalMangledTable = false;
          for (const value of globalMangledTable.values()) {
            if (value === tmpName) {
              isInGlobalMangledTable = true;
              break;
            }
          }

          if (isInGlobalMangledTable) {
            continue;
          }

          let isInHistoryMangledTable = false;
          if (historyMangledTable) {
            for (const value of historyMangledTable.values()) {
              if (value === tmpName) {
                isInHistoryMangledTable = true;
                break;
              }
            }
          }

          if (!isInHistoryMangledTable) {
            mangledName = tmpName;
            break;
          }
        }

        globalMangledTable.set(original, mangledName);
        return mangledName;
      }

      function isExcludeScope(scope: Scope): boolean {
        if (isClassScope(scope)) {
          return true;
        }

        if (isInterfaceScope(scope)) {
          return true;
        }

        if (isEnumScope(scope)) {
          return true;
        }

        return isObjectLiteralScope(scope);
      }

      function searchMangledInParent(scope: Scope, name: string): boolean {
        let found: boolean = false;
        let parentScope = scope;
        while (parentScope) {
          if (parentScope.mangledNames.has(name)) {
            found = true;
            break;
          }

          parentScope = parentScope.parent;
        }

        return found;
      }

      function getMangled(scope: Scope, localGenerator: INameGenerator): string {
        let mangled: string = '';
        do {
          mangled = localGenerator.getName()!;
          // if it is a globally reserved name, it needs to be regenerated
          if (reservedNames.includes(mangled)) {
            mangled = '';
            continue;
          }

          if (scope.exportNames && scope.exportNames.has(mangled)) {
            mangled = '';
            continue;
          }

          if (historyMangledNames && historyMangledNames.has(mangled)) {
            mangled = '';
            continue;
          }

          if (searchMangledInParent(scope, mangled)) {
            mangled = '';
            continue;
          }

          if ((profile.mRenameProperties && manager.getRootScope().constructorReservedParams.has(mangled)) ||
            ApiExtractor.mConstructorPropertySet?.has(mangled)) {
            mangled = '';
          }
        } while (mangled === '');

        return mangled;
      }

      function renameLabelsInScope(scope: Scope): void {
        const labels: Label[] = scope.labels;
        if (labels.length > 0) {
          let upperMangledLabels = getUpperMangledLabelNames(labels[0]);
          for (const label of labels) {
            let mangledLabel = getMangledLabel(label, upperMangledLabels);
            mangledLabelNames.set(label, mangledLabel);
          }
        }
      }

      function getMangledLabel(label: Label, mangledLabels: string[]): string {
        let mangledLabel: string = '';
        do {
          mangledLabel = generator.getName();
          if (mangledLabel === label.name) {
            mangledLabel = '';
          }

          if (mangledLabels.includes(mangledLabel)) {
            mangledLabel = '';
          }
        } while (mangledLabel === '');

        return mangledLabel;
      }

      function getUpperMangledLabelNames(label: Label): string[] {
        const results: string[] = [];
        let parent: Label = label.parent;
        while (parent) {
          let mangledLabelName: string = mangledLabelNames.get(parent);
          if (mangledLabelName) {
            results.push(mangledLabelName);
          }
          parent = parent.parent;
        }

        return results;
      }

      /**
       * visit each node to change identifier name to mangled name
       *  - calculate shadow name index to find shadow node
       * @param node
       */
      function visit(node: Node): Node {
        if (!isIdentifier(node) || !node.parent) {
          return visitEachChild(node, visit, context);
        }

        if (isLabeledStatement(node.parent) || isBreakOrContinueStatement(node.parent)) {
          identifierIndex += 1;
          return updateLabelNode(node);
        }

        const shadowNode: Identifier = shadowIdentifiers[identifierIndex];
        identifierIndex += 1;
        return updateNameNode(node, shadowNode);
      }

      function tryRemoveVirtualConstructor(node: Node): Node {
        if (isStructDeclaration(node)) {
          const shadowNode: StructDeclaration = shadowStructs[structIndex];
          structIndex++;
          const sourceFile = NodeUtils.getSourceFileOfNode(shadowNode);
          const tempStructMembers: ClassElement[] = [];
          if (sourceFile && sourceFile.isDeclarationFile) {
            for (let index = 0; index < node.members.length; index++) {
              const member = node.members[index];
              // @ts-ignore
              if (isConstructorDeclaration(member) && shadowNode.members[index].virtual) {
                continue;
              }
              tempStructMembers.push(member);
            }
            const structMembersWithVirtualConstructor = factory.createNodeArray(tempStructMembers);
            return factory.updateStructDeclaration(node, node.modifiers, node.name, node.typeParameters, node.heritageClauses,
              structMembersWithVirtualConstructor);
          }
        }
        return visitEachChild(node, tryRemoveVirtualConstructor, context);
      }

      function updateNameNode(node: Identifier, shadowNode: Identifier): Node {
        // skip property in property access expression
        if (NodeUtils.isPropertyAccessNode(node)) {
          return node;
        }

        let sym: Symbol | undefined = checker.getSymbolAtLocation(shadowNode);
        let mangledPropertyNameOfNoSymbolImportExport = '';
        if ((!sym || sym.name === 'default')) {
          if (exportObfuscation && noSymbolIdentifier.has(shadowNode.escapedText as string) && trySearchImportExportSpecifier(shadowNode)) {
            mangledPropertyNameOfNoSymbolImportExport = mangleNoSymbolImportExportPropertyName(shadowNode.escapedText as string);
          } else {
            return node;
          }
        }

        let mangledName: string = mangledSymbolNames.get(sym);
        if (!mangledName && mangledPropertyNameOfNoSymbolImportExport !== '') {
          mangledName = mangledPropertyNameOfNoSymbolImportExport;
        }

        if (!mangledName || mangledName === sym?.name) {
          return node;
        }

        return factory.createIdentifier(mangledName);
      }

      function updateLabelNode(node: Identifier): Node {
        let label: Label | undefined;
        let labelName: string = '';

        mangledLabelNames.forEach((value, key) => {
          if (key.refs.includes(node)) {
            label = key;
            labelName = value;
          }
        });

        return label ? factory.createIdentifier(labelName) : node;
      }

      /**
       * import {A as B} from 'modulename';
       * import {C as D} from 'modulename';
       * export {E as F};
       * above A、C、F have no symbol, so deal with them specially.
       */
      function mangleNoSymbolImportExportPropertyName(original: string): string {
        const path: string = '#' + original;
        const historyName: string = historyNameCache?.get(path);
        let mangled = historyName ?? getPropertyMangledName(original);
        nameCache.set(path, mangled);
        return mangled;
      }

      function trySearchImportExportSpecifier(node: Node): boolean {
        while (node.parent) {
          node = node.parent;
          if ((isImportSpecifier(node) || isExportSpecifier(node)) && node.propertyName && isIdentifier(node.propertyName)) {
            return true;
          }
        }
        return false;
      }
    }
  };

  function isSkippedGlobal(enableTopLevel: boolean, scope: Scope): boolean {
    return !enableTopLevel && isGlobalScope(scope);
  }

  export let transformerPlugin: TransformPlugin = {
    'name': 'renameIdentifierPlugin',
    'order': (1 << TransformerOrder.RENAME_IDENTIFIER_TRANSFORMER),
    'createTransformerFactory': createRenameIdentifierFactory
  };

  export let nameCache: Map<string, string> = undefined;
  export let historyNameCache: Map<string, string> = undefined;
  export let globalNameCache: Map<string, string> = new Map();
}

export = secharmony;