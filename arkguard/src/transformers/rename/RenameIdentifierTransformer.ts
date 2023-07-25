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
  isIdentifier,
  isLabeledStatement,
  isSourceFile,
  setParentRecursive,
  visitEachChild,
} from 'typescript';

import type {
  Identifier,
  Node,
  SourceFile,
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
  isObjectLiteralScope
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
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';
import {TypeUtils} from '../../utils/TypeUtils';
import {collectIdentifiers} from '../../utils/TransformUtil';
import {NodeUtils} from '../../utils/NodeUtils';

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

    const openTopLevel: boolean = option?.mTopLevel;
    return renameIdentifierFactory;

    function renameIdentifierFactory(context: TransformationContext): Transformer<Node> {
      let reservedNames: string[] = [...(profile?.mReservedNames ?? []), 'this', '__global'];
      let mangledSymbolNames: Map<Symbol, string> = new Map<Symbol, string>();
      let mangledLabelNames: Map<Label, string> = new Map<Label, string>();

      let options: NameGeneratorOptions = {};
      if (profile.mNameGeneratorType === NameGeneratorType.HEX) {
        options.hexWithPrefixSuffix = true;
      }

      let generator: INameGenerator = getNameGenerator(profile.mNameGeneratorType, options);

      let historyMangledNames: Set<string> = undefined;
      if (historyNameCache && historyNameCache.size > 0) {
        historyMangledNames = new Set<string>(Array.from(historyNameCache.values()));
      }

      let checker: TypeChecker = undefined;
      let manager: ScopeManager = createScopeManager();
      let shadowIdentifiers: Identifier[] = undefined;

      let identifierIndex: number = 0;
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
        manager.analyze(shadowSourceAst, checker);

        manager.getReservedNames().forEach((name) => {
          reservedNames.push(name);
        });
        // collect all identifiers of shadow sourceFile
        shadowIdentifiers = collectIdentifiers(shadowSourceAst, context);

        if (nameCache === undefined) {
          nameCache = new Map<string, string>();
        }

        let root: Scope = manager.getRootScope();
        renameInScope(root);
        return setParentRecursive(visit(node), true);
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

        for (const subScope of scope.children) {
          renameInScope(subScope);
        }
      }

      function renameNamesInScope(scope: Scope): void {
        if (scope.parent) {
          scope.parent.mangledNames.forEach((value) => {
            scope.mangledNames.add(value);
          });

          scope.parent.importNames.forEach((value) => {
            scope.importNames.add(value);
          });
        }

        if (isExcludeScope(scope)) {
          return;
        }

        scope.defs.forEach((def) => {
          if (scope.importNames.has(def.name)) {
            scope.defs.delete(def);
          }
        });

        generator.reset();
        renames(scope, scope.defs, generator);
      }

      function renames(scope: Scope, defs: Set<Symbol>, generator: INameGenerator): void {
        const localCache: Map<string, string> = new Map<string, string>();
        findNoSymbolIdentifiers(scope);

        defs.forEach((def) => {
          const original: string = def.name;
          let mangled: string = original;
          // No allow to rename reserved names.
          if (reservedNames.includes(original) || scope.exportNames.has(def.name) || isSkippedGlobal(openTopLevel, scope)) {
            scope.mangledNames.add(mangled);
            mangledSymbolNames.set(def, mangled);
            return;
          }

          if (mangledSymbolNames.has(def)) {
            return;
          }

          const path: string = scope.loc + '#' + original;
          const historyName: string = historyNameCache?.get(path);
          const specifyName: string = historyName ? historyName : nameCache.get(path);
          if (specifyName) {
            mangled = specifyName;
          } else {
            const sameMangled: string = localCache.get(original);
            mangled = sameMangled ? sameMangled : getMangled(scope, generator);
          }

          // add new names to name cache
          nameCache.set(path, mangled);
          scope.mangledNames.add(mangled);
          mangledSymbolNames.set(def, mangled);
          localCache.set(original, mangled);
        });
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

      function getMangled(scope: Scope, localGenerator: INameGenerator): string {
        let mangled: string = '';
        do {
          mangled = localGenerator.getName()!;
          // if it is a globally reserved name, it needs to be regenerated
          if (reservedNames.includes(mangled)) {
            mangled = '';
            continue;
          }

          if (scope.importNames && scope.importNames.has(mangled)) {
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

          // the anme has already been generated in the current scope
          if (scope.mangledNames.has(mangled)) {
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

      function findNoSymbolIdentifiers(scope: Scope): void {
        const noSymbolVisit = (targetNode: Node): void => {
          if (!isIdentifier(targetNode)) {
            forEachChild(targetNode, noSymbolVisit);
            return;
          }

          // skip property in property access expression
          if (NodeUtils.isPropertyAccessNode(targetNode)) {
            return;
          }

          const sym: Symbol | undefined = checker.getSymbolAtLocation(targetNode);
          if (!sym) {
            scope.mangledNames.add((targetNode as Identifier).escapedText.toString());
          }
        };

        noSymbolVisit(scope.block);
      }

      function updateNameNode(node: Identifier, shadowNode: Identifier): Node {
        // skip property in property access expression
        if (NodeUtils.isPropertyAccessNode(node)) {
          return node;
        }

        const sym: Symbol | undefined = checker.getSymbolAtLocation(shadowNode);
        if (!sym || sym.name === 'default') {
          return node;
        }

        const mangledName: string = mangledSymbolNames.get(sym);
        if (!mangledName || mangledName === sym.name) {
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
    }
  };

  function isSkippedGlobal(enableTopLevel: boolean, scope: Scope): boolean {
    return !enableTopLevel && isGlobalScope(scope);
  }

  const TRANSFORMER_ORDER: number = 9;
  export let transformerPlugin: TransformPlugin = {
    'name': 'renameIdentifierPlugin',
    'order': (1 << TRANSFORMER_ORDER),
    'createTransformerFactory': createRenameIdentifierFactory
  };

  export let nameCache: Map<string, string> = undefined;
  export let historyNameCache: Map<string, string> = undefined;
}

export = secharmony;
