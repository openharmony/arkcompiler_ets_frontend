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
  isStringLiteral,
  isExportDeclaration,
  isImportDeclaration,
  isSourceFile,
  setParentRecursive,
  visitEachChild,
  isStructDeclaration,
  SyntaxKind,
  isConstructorDeclaration,
} from 'typescript';

import type {
  CallExpression,
  Expression,
  ImportDeclaration,
  ExportDeclaration,
  Node,
  StringLiteral,
  TransformationContext,
  Transformer,
  StructDeclaration,
  SourceFile,
  ClassElement,
  ImportCall,
  TransformerFactory,
} from 'typescript';

import fs from 'fs';
import path from 'path';

import type { IOptions } from '../../configs/IOptions';
import type { TransformPlugin } from '../TransformPlugin';
import { TransformerOrder } from '../TransformPlugin';
import type { IFileNameObfuscationOption } from '../../configs/INameObfuscationOption';
import { NameGeneratorType, getNameGenerator } from '../../generator/NameFactory';
import type { INameGenerator, NameGeneratorOptions } from '../../generator/INameGenerator';
import { FileUtils } from '../../utils/FileUtils';
import { NodeUtils } from '../../utils/NodeUtils';
import { orignalFilePathForSearching } from '../../ArkObfuscator';
import type { PathAndExtension } from '../../common/type';
namespace secharmony {

  // global mangled file name table used by all files in a project
  export let globalFileNameMangledTable: Map<string, string> = undefined;

  // used for file name cache
  export let historyFileNameMangledTable: Map<string, string> = undefined;

  let profile: IFileNameObfuscationOption | undefined;
  let generator: INameGenerator | undefined;
  let reservedFileNames: Set<string> | undefined;
  /**
   * Rename Properties Transformer
   *
   * @param option obfuscation options
   */
  const createRenameFileNameFactory = function (options: IOptions): TransformerFactory<Node> {
    profile = options?.mRenameFileName;
    if (!profile || !profile.mEnable) {
      return null;
    }

    return renameFileNameFactory;

    function renameFileNameFactory(context: TransformationContext): Transformer<Node> {
      let options: NameGeneratorOptions = {};
      if (profile.mNameGeneratorType === NameGeneratorType.HEX) {
        options.hexWithPrefixSuffix = true;
      }

      generator = getNameGenerator(profile.mNameGeneratorType, options);
      let tempReservedFileNameOrPath: string[] = profile?.mReservedFileNames ?? [];
      let tempReservedFileName: string[] = ['.', '..', ''];
      tempReservedFileNameOrPath.map(fileNameOrPath => {
        if (fileNameOrPath && fileNameOrPath.length > 0) {
          const directories = FileUtils.splitFilePath(fileNameOrPath);
          directories.forEach(directory => {
            tempReservedFileName.push(directory);
            const pathOrExtension: PathAndExtension = FileUtils.getFileSuffix(directory);
            if (pathOrExtension.ext) {
              tempReservedFileName.push(pathOrExtension.ext);
              tempReservedFileName.push(pathOrExtension.path);
            }
          });
        }
      });
      reservedFileNames = new Set<string>(tempReservedFileName);

      return renameFileNameTransformer;

      function renameFileNameTransformer(node: Node): Node {
        if (globalFileNameMangledTable === undefined) {
          globalFileNameMangledTable = new Map<string, string>();
        }

        let ret: Node = updateNodeInfo(node);
        if (isSourceFile(ret)) {
          const orignalAbsPath = ret.fileName;
          const mangledAbsPath: string = getMangleCompletePath(orignalAbsPath);
          ret.fileName = mangledAbsPath;
        }
        return setParentRecursive(ret, true);
      }

      function updateNodeInfo(node: Node): Node {
        if (isImportDeclaration(node) || isExportDeclaration(node)) {
          return updateImportOrExportDeclaration(node);
        }

        if (isImportCall(node)) {
          return tryUpdateDynamicImport(node);
        }

        if (isStructDeclaration(node)) {
          return tryRemoveVirtualConstructor(node);
        }
        return visitEachChild(node, updateNodeInfo, context);
      }
    }
  };

  function updateImportOrExportDeclaration(node: ImportDeclaration | ExportDeclaration): ImportDeclaration | ExportDeclaration {
    if (!node.moduleSpecifier) {
      return node;
    }
    const mangledModuleSpecifier = renameStringLiteral(node.moduleSpecifier as StringLiteral);
    if (isImportDeclaration(node)) {
      return factory.updateImportDeclaration(node, node.modifiers, node.importClause, mangledModuleSpecifier as Expression, node.assertClause);
    } else {
      return factory.updateExportDeclaration(node, node.modifiers, node.isTypeOnly, node.exportClause, mangledModuleSpecifier as Expression,
        node.assertClause);
    }
  }

  function isImportCall(n: Node): n is ImportCall {
    return n.kind === SyntaxKind.CallExpression && (<CallExpression>n).expression.kind === SyntaxKind.ImportKeyword;
  }

  // dynamic import example: let module = import('./a')
  function tryUpdateDynamicImport(node: CallExpression): CallExpression {
    if (node.expression && node.arguments.length === 1 && isStringLiteral(node.arguments[0])) {
      const obfuscatedArgument = [renameStringLiteral(node.arguments[0] as StringLiteral)];
      if (obfuscatedArgument[0] !== node.arguments[0]) {
        return factory.updateCallExpression(node, node.expression, node.typeArguments, obfuscatedArgument);
      }
    }
    return node;
  }

  function renameStringLiteral(node: StringLiteral): Expression {
    let expr: StringLiteral = renameFileName(node) as StringLiteral;
    if (expr !== node) {
      return factory.createStringLiteral(expr.text);
    }
    return node;
  }

  function renameFileName(node: StringLiteral): Node {
    let original: string = '';
    original = node.text;
    original = original.replace(/\\/g, '/');

    if (!canBeObfuscatedFilePath(original)) {
      return node;
    }

    let mangledFileName: string = getMangleIncompletePath(original);
    if (mangledFileName === original) {
      return node;
    }

    return factory.createStringLiteral(mangledFileName);
  }

  export function getMangleCompletePath(originalCompletePath: string): string {
    originalCompletePath = toUnixPath(originalCompletePath);
    const { path: filePathWithoutSuffix, ext: extension } = FileUtils.getFileSuffix(originalCompletePath);
    const mangleFilePath = manglFileName(filePathWithoutSuffix);
    return mangleFilePath + extension;
  }

  function getMangleIncompletePath(orignalPath: string): string | undefined {
    const pathAndExtension : PathAndExtension | undefined = tryValidateFileExisting(orignalPath);
    if (!pathAndExtension) {
      return orignalPath;
    }

    if (pathAndExtension.ext) {
      const mangleFilePath = manglFileName(pathAndExtension.path);
      return mangleFilePath;
    } else {
      const { path: filePathWithoutSuffix, ext: extension } = FileUtils.getFileSuffix(pathAndExtension.path);
      const mangleFilePath = manglFileName(filePathWithoutSuffix);
      return mangleFilePath + extension;
    }
  }

  function manglFileName(orignalPath: string): string {
    const originalFileNameSegments: string[] = FileUtils.splitFilePath(orignalPath);
    const mangledSegments: string[] = originalFileNameSegments.map(originalSegment => mangleFileNamePart(originalSegment));
    let mangledFileName: string = mangledSegments.join('/');
    return mangledFileName;
  }

  function mangleFileNamePart(original: string): string {
    if (reservedFileNames.has(original)) {
      return original;
    }

    const historyName: string = historyFileNameMangledTable?.get(original);
    let mangledName: string = historyName ? historyName : globalFileNameMangledTable.get(original);

    while (!mangledName) {
      mangledName = generator.getName();
      if (mangledName === original || reservedFileNames.has(mangledName)) {
        mangledName = null;
        continue;
      }

      let reserved: string[] = [...globalFileNameMangledTable.values()];
      if (reserved.includes(mangledName)) {
        mangledName = null;
        continue;
      }

      if (historyFileNameMangledTable && [...historyFileNameMangledTable.values()].includes(mangledName)) {
        mangledName = null;
        continue;
      }
    }
    globalFileNameMangledTable.set(original, mangledName);
    return mangledName;
  }

  export let transformerPlugin: TransformPlugin = {
    'name': 'renamePropertiesPlugin',
    'order': (1 << TransformerOrder.RENAME_FILE_NAME_TRANSFORMER),
    'createTransformerFactory': createRenameFileNameFactory
  };
}

export = secharmony;

function canBeObfuscatedFilePath(filePath: string): boolean {
  return path.isAbsolute(filePath) || FileUtils.isRelativePath(filePath);
}

// typescript doesn't add the json extension.
const extensionOrder: string[] = ['.ets', '.ts', '.d.ets', '.d.ts', '.js'];

function tryValidateFileExisting(importPath: string): PathAndExtension | undefined {
  let fileAbsPath: string = '';
  if (path.isAbsolute(importPath)) {
    fileAbsPath = importPath;
  } else {
    fileAbsPath = path.join(path.dirname(orignalFilePathForSearching), importPath);
  }
  
  const filePathExtensionLess: string = path.normalize(fileAbsPath);
  for (let ext of extensionOrder) {
    const targetPath = filePathExtensionLess + ext;
    if (fs.existsSync(targetPath)) {
      return {path: importPath, ext: ext};
    }
  }

  // all suffixes are not matched, search this file directly.
  if (fs.existsSync(filePathExtensionLess)) {
    return { path: importPath, ext: undefined };
  }
  return undefined;
}

function tryRemoveVirtualConstructor(node: StructDeclaration): StructDeclaration {
  const sourceFile = NodeUtils.getSourceFileOfNode(node);
  const tempStructMembers: ClassElement[] = [];
  if (sourceFile && sourceFile.isDeclarationFile && NodeUtils.isInETSFile(sourceFile)) {
    for (let member of node.members) {
      // @ts-ignore
      if (!isConstructorDeclaration(member) || !member.virtual) {
        tempStructMembers.push(member);
      }
    }
    const structMembersWithVirtualConstructor = factory.createNodeArray(tempStructMembers);
    return factory.updateStructDeclaration(node, node.modifiers, node.name, node.typeParameters, node.heritageClauses, structMembersWithVirtualConstructor);
  }
  return node;
}

function toUnixPath(data: string): string {
  if (/^win/.test(require('os').platform())) {
    const fileTmps: string[] = data.split(path.sep);
    const newData: string = path.posix.join(...fileTmps);
    return newData;
  }
  return data;
}