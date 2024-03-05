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
import { FileUtils, BUNDLE } from '../../utils/FileUtils';
import { NodeUtils } from '../../utils/NodeUtils';
import { orignalFilePathForSearching, performancePrinter } from '../../ArkObfuscator';
import type { PathAndExtension, ProjectInfo } from '../../common/type';
import { EventList } from '../../utils/PrinterUtils';
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
  const createRenameFileNameFactory = function (options: IOptions, projectInfo?: ProjectInfo): TransformerFactory<Node> {
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

        performancePrinter?.singleFilePrinter?.startEvent(EventList.FILENAME_OBFUSCATION, performancePrinter.timeSumPrinter);
        let ret: Node = updateNodeInfo(node);
        if (!inInOhModules(projectInfo, orignalFilePathForSearching) && isSourceFile(ret)) {
          const orignalAbsPath = ret.fileName;
          const mangledAbsPath: string = getMangleCompletePath(orignalAbsPath);
          ret.fileName = mangledAbsPath;
        }
        let parentNodes = setParentRecursive(ret, true);
        performancePrinter?.singleFilePrinter?.endEvent(EventList.FILENAME_OBFUSCATION, performancePrinter.timeSumPrinter);
        return parentNodes;
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

  export function inInOhModules(proInfo: ProjectInfo, originalPath: string): boolean {
    let ohPackagePath: string = '';
    if (proInfo && proInfo.projectRootPath && proInfo.packageDir) {
      ohPackagePath = FileUtils.toUnixPath(path.resolve(proInfo.projectRootPath, proInfo.packageDir));
    }
    return ohPackagePath && FileUtils.toUnixPath(originalPath).indexOf(ohPackagePath) !== -1;
  }

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
    originalCompletePath = FileUtils.toUnixPath(originalCompletePath);
    const { path: filePathWithoutSuffix, ext: extension } = FileUtils.getFileSuffix(originalCompletePath);
    const mangleFilePath = mangleFileName(filePathWithoutSuffix);
    return mangleFilePath + extension;
  }

  function getMangleIncompletePath(orignalPath: string): string {
    // The ohmUrl format does not have file extension
    if (isBundleOhmUrl(orignalPath)) {
      const mangledOhmUrl = mangleOhmUrl(orignalPath);
      return mangledOhmUrl;
    }

    // Try to concat the extension for orignalPath.
    const pathAndExtension : PathAndExtension | undefined = tryValidateFileExisting(orignalPath);
    if (!pathAndExtension) {
      return orignalPath;
    }

    if (pathAndExtension.ext) {
      const mangleFilePath = mangleFileName(pathAndExtension.path);
      return mangleFilePath;
    }
    /**
     * import * from './filename1.js'. We just need to obfuscate 'filename1' and then concat the extension 'js'.
     * import * from './direcotry'. For the grammar of importing directory, TSC will look for index.ets/index.ts when parsing.
     * We obfuscate directory name and do not need to concat extension.
     */
    const { path: filePathWithoutSuffix, ext: extension } = FileUtils.getFileSuffix(pathAndExtension.path);
    const mangleFilePath = mangleFileName(filePathWithoutSuffix);
    return mangleFilePath + extension;
  }

  export function mangleOhmUrl(ohmUrl: string): string {
    const originalOhmUrlSegments: string[] = FileUtils.splitFilePath(ohmUrl);
    /**
     * OhmUrl Format:
     * fixed parts in hap/hsp: @bundle:${bundleName}/${moduleName}/
     * fixed parts in har: @bundle:${bundleName}/${moduleName}@${harName}/
     * hsp example: @bundle:com.example.myapplication/entry/index
     * har example: @bundle:com.example.myapplication/entry@library_test/index
     * we do not mangle fixed parts.
     */
    const prefixSegments: string[] = originalOhmUrlSegments.slice(0, 2); // 2: length of fixed parts in array
    const urlSegments: string[] = originalOhmUrlSegments.slice(2); // 2: index of mangled parts in array
    const mangledOhmUrlSegments: string[] = urlSegments.map(originalSegment => mangleFileNamePart(originalSegment));
    let mangledOhmUrl: string = prefixSegments.join('/') + '/' + mangledOhmUrlSegments.join('/');
    return mangledOhmUrl;
  }

  function mangleFileName(orignalPath: string): string {
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
  return path.isAbsolute(filePath) || FileUtils.isRelativePath(filePath) || isBundleOhmUrl(filePath);
}

function isBundleOhmUrl(filePath: string): boolean{
  return filePath.startsWith(BUNDLE);
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
