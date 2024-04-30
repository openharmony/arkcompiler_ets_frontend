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

import type {
  ModifiersArray,
  Node,
  ParameterDeclaration,
  SourceFile
} from 'typescript';

import {
  createSourceFile,
  forEachChild,
  isBinaryExpression,
  isClassDeclaration,
  isClassExpression,
  isStructDeclaration,
  isExpressionStatement,
  isEnumDeclaration,
  isExportAssignment,
  isExportDeclaration,
  isExportSpecifier,
  isIdentifier,
  isInterfaceDeclaration,
  isObjectLiteralExpression,
  isTypeAliasDeclaration, 
  isVariableDeclaration,
  isVariableStatement,
  isElementAccessExpression,
  isPropertyAccessExpression,
  isStringLiteral,
  ScriptTarget,
  SyntaxKind,
  sys,
  isConstructorDeclaration,
  getModifiers
} from 'typescript';

import fs from 'fs';
import path from 'path';
import json5 from 'json5';

import {
  getClassProperties,
  getElementAccessExpressionProperties,
  getEnumProperties, getInterfaceProperties,
  getObjectProperties,
  getTypeAliasProperties,
  isParameterPropertyModifier,
} from '../utils/OhsUtil';
import { scanProjectConfig } from './ApiReader';
import { stringPropsSet } from '../utils/OhsUtil';
import type { IOptions } from '../configs/IOptions';
import { FileUtils } from '../utils/FileUtils';
import { supportedParsingExtension } from './type';

export namespace ApiExtractor {
  interface KeywordInfo {
    hasExport: boolean,
    hasDeclare: boolean
  }

  export enum ApiType {
    API = 1,
    COMPONENT = 2,
    PROJECT_DEPENDS = 3,
    PROJECT = 4,
    CONSTRUCTOR_PROPERTY = 5
  }

  let mCurrentExportedPropertySet: Set<string> = new Set<string>();
  let mCurrentExportNameSet: Set<string> = new Set<string>();
  export let mPropertySet: Set<string> = new Set<string>();
  export let mLibExportNameSet: Set<string> = new Set<string>();
  export let mConstructorPropertySet: Set<string> = undefined;
  export let mSystemExportSet: Set<string> = new Set<string>();
  /**
   * filter classes or interfaces with export, default, etc
   */
  const getKeyword = function (modifiers: ModifiersArray): KeywordInfo {
    if (modifiers === undefined) {
      return {hasExport: false, hasDeclare: false};
    }

    let hasExport: boolean = false;
    let hasDeclare: boolean = false;

    for (const modifier of modifiers) {
      if (modifier.kind === SyntaxKind.ExportKeyword) {
        hasExport = true;
      }

      if (modifier.kind === SyntaxKind.DeclareKeyword) {
        hasDeclare = true;
      }
    }

    return {hasExport: hasExport, hasDeclare: hasDeclare};
  };

  /**
   * get export name list
   * @param astNode
   */
  const visitExport = function (astNode): void {
    if (isExportAssignment(astNode)) {
      if (!mCurrentExportNameSet.has(astNode.expression.getText())) {
        mCurrentExportNameSet.add(astNode.expression.getText());
        mCurrentExportedPropertySet.add(astNode.expression.getText());
      }

      return;
    }

    let {hasExport, hasDeclare} = getKeyword(astNode.modifiers);
    if (!hasExport) {
      addCommonJsExports(astNode);
      return;
    }

    if (astNode.name) {
      if (!mCurrentExportNameSet.has(astNode.name.getText())) {
        mCurrentExportNameSet.add(astNode.name.getText());
        mCurrentExportedPropertySet.add(astNode.name.getText());
      }

      return;
    }

    if (hasDeclare && astNode.declarationList) {
      astNode.declarationList.declarations.forEach((declaration) => {
        const declarationName = declaration.name.getText();
        if (!mCurrentExportNameSet.has(declarationName)) {
          mCurrentExportNameSet.add(declarationName);
          mCurrentExportedPropertySet.add(declarationName);
        }
      });
    }
  };

  const checkPropertyNeedVisit = function (astNode): boolean {
    if (astNode.name && !mCurrentExportNameSet.has(astNode.name.getText())) {
      return false;
    }

    if (astNode.name === undefined) {
      let {hasDeclare} = getKeyword(astNode.modifiers);
      if (hasDeclare && astNode.declarationList &&
        !mCurrentExportNameSet.has(astNode.declarationList.declarations[0].name.getText())) {
        return false;
      }
    }

    return true;
  };

  /**
   * used only in oh sdk api extract or api of xxx.d.ts declaration file
   * @param astNode
   */
  const visitChildNode = function (astNode): void {
    if (!astNode) {
      return;
    }

    if (astNode.name !== undefined && !mCurrentExportedPropertySet.has(astNode.name.getText())) {
      if (isStringLiteral(astNode.name)) {
        mCurrentExportedPropertySet.add(astNode.name.text);
      } else {
        mCurrentExportedPropertySet.add(astNode.name.getText());
      }
    }

    astNode.forEachChild((childNode) => {
      visitChildNode(childNode);
    });
  };

  // Collect constructor properties from all files.
  const visitNodeForConstructorProperty = function (astNode): void {
    if (!astNode) {
      return;
    }

    if (isConstructorDeclaration) {
      const visitParam = (param: ParameterDeclaration): void => {
        const modifiers = getModifiers(param);
        if (!modifiers || modifiers.length <= 0) {
          return;
        }

        const findRet = modifiers.find(modifier => isParameterPropertyModifier(modifier));
        if (!isIdentifier(param.name) || findRet === undefined) {
          return;
        }
        mConstructorPropertySet?.add(param.name.getText());
      };

      astNode?.parameters?.forEach((param) => {
        visitParam(param);
      });
    }

    astNode.forEachChild((childNode) => {
      visitNodeForConstructorProperty(childNode);
    });
  };
  /**
   * visit ast of a file and collect api list
   * used only in oh sdk api extract
   * @param astNode node of ast
   */
  const visitPropertyAndName = function (astNode): void {
    if (!checkPropertyNeedVisit(astNode)) {
      return;
    }

    visitChildNode(astNode);
  };

  /**
   * commonjs exports extract
   * examples:
   * - exports.A = 1;
   * - exports.B = hello; // hello can be variable or class ...
   * - exports.C = {};
   * - exports.D = class {};
   * - exports.E = function () {}
   * - class F {}
   * - exports.F = F;
   * - module.exports = {G: {}}
   * - ...
   */
  const addCommonJsExports = function (astNode): void {
    if (!isExpressionStatement(astNode) || !astNode.expression) {
      return;
    }

    const expression = astNode.expression;
    if (!isBinaryExpression(expression)) {
      return;
    }

    const left = expression.left;
    if (!isElementAccessExpression(left) && !isPropertyAccessExpression(left)) {
      return;
    }

    if ((left.expression.getText() !== 'exports' && !isModuleExports(left)) ||
      expression.operatorToken.kind !== SyntaxKind.EqualsToken) {
      return;
    }

    if (isElementAccessExpression(left)) {
      if (isStringLiteral(left.argumentExpression)) {
        mCurrentExportedPropertySet.add(left.argumentExpression.text);
      }
    }

    if (isPropertyAccessExpression(left)) {
      if (isIdentifier(left.name)) {
        mCurrentExportedPropertySet.add(left.name.getText());
      }
    }

    if (isIdentifier(expression.right)) {
      mCurrentExportNameSet.add(expression.right.getText());
      return;
    }

    if (isClassDeclaration(expression.right) || isClassExpression(expression.right)) {
      getClassProperties(expression.right, mCurrentExportedPropertySet);
      return;
    }

    if (isObjectLiteralExpression(expression.right)) {
      getObjectProperties(expression.right, mCurrentExportedPropertySet);
    }

    return;
  };

  // module.exports = { p1: 1 }
  function isModuleExports(astNode: Node): boolean {
    if (isPropertyAccessExpression(astNode)) {
      if (isIdentifier(astNode.expression) && astNode.expression.escapedText.toString() === 'module' &&
        isIdentifier(astNode.name) && astNode.name.escapedText.toString() === 'exports') {
        return true;
      }
    }
    return false;
  }

  /**
   * extract project export name
   * - export {xxx, xxx};
   * - export {xxx as xx, xxx as xx};
   * - export default function/class/...{};
   * - export class xxx{}
   * - ...
   * @param astNode
   */
  const visitProjectExport = function (astNode): void {
    if (isExportAssignment(astNode)) {
      // let xxx; export default xxx = a;
      if (isBinaryExpression(astNode.expression)) {
        if (isObjectLiteralExpression(astNode.expression.right)) {
          getObjectProperties(astNode.expression.right, mCurrentExportedPropertySet);
          return;
        }

        if (isClassExpression(astNode.expression.right)) {
          getClassProperties(astNode.expression.right, mCurrentExportedPropertySet);
        }

        return;
      }

      // export = xxx; The xxx here can't be obfuscated
      // export default yyy; The yyy here can be obfuscated
      if (isIdentifier(astNode.expression)) {
        if (!mCurrentExportNameSet.has(astNode.expression.getText())) {
          mCurrentExportNameSet.add(astNode.expression.getText());
          mCurrentExportedPropertySet.add(astNode.expression.getText());
        }
        return;
      }

      if (isObjectLiteralExpression(astNode.expression)) {
        getObjectProperties(astNode.expression, mCurrentExportedPropertySet);
      }

      return;
    }

    if (isExportDeclaration(astNode)) {
      if (astNode.exportClause) {
        if (astNode.exportClause.kind === SyntaxKind.NamedExports) {
          astNode.exportClause.forEachChild((child) => {
            if (!isExportSpecifier(child)) {
              return;
            }

            if (child.propertyName) {
              mCurrentExportNameSet.add(child.propertyName.getText());
            }

            let exportName = child.name.getText();
            mCurrentExportedPropertySet.add(exportName);
            mCurrentExportNameSet.add(exportName);
          });
        }

        if (astNode.exportClause.kind === SyntaxKind.NamespaceExport) {
          mCurrentExportedPropertySet.add(astNode.exportClause.name.getText());
          return;
        }
      }
      return;
    }

    let {hasExport} = getKeyword(astNode.modifiers);
    if (!hasExport) {
      addCommonJsExports(astNode);
      forEachChild(astNode, visitProjectExport);
      return;
    }

    if (astNode.name) {
      if (!mCurrentExportNameSet.has(astNode.name.getText())) {
        mCurrentExportNameSet.add(astNode.name.getText());
        mCurrentExportedPropertySet.add(astNode.name.getText());
      }

      forEachChild(astNode, visitProjectExport);
      return;
    }

    if (isClassDeclaration(astNode)) {
      getClassProperties(astNode, mCurrentExportedPropertySet);
      return;
    }

    if (isVariableStatement(astNode)) {
      astNode.declarationList.forEachChild((child) => {
        if (isVariableDeclaration(child) && !mCurrentExportNameSet.has(child.name.getText())) {
          mCurrentExportNameSet.add(child.name.getText());
          mCurrentExportedPropertySet.add(child.name.getText());
        }
      });

      return;
    }

    forEachChild(astNode, visitProjectExport);
  };

  /**
   * extract the class, enum, and object properties of the export in the project before obfuscation
   * class A{};
   * export = A; need to be considered
   * export = namespace;
   * This statement also needs to determine whether there is an export in the namespace, and namespaces are also allowed in the namespace
   * @param astNode
   */
  const visitProjectNode = function (astNode): void {
    const currentPropsSet: Set<string> = new Set();
    let nodeName: string | undefined = astNode.name?.text;
    if ((isClassDeclaration(astNode) || isStructDeclaration(astNode))) {
      getClassProperties(astNode, currentPropsSet);
    } else if (isEnumDeclaration(astNode)) { // collect export enum structure properties
      getEnumProperties(astNode, currentPropsSet);
    } else if (isVariableDeclaration(astNode)) {
      if (astNode.initializer) {
        if (isObjectLiteralExpression(astNode.initializer)) {
          getObjectProperties(astNode.initializer, currentPropsSet);
        } else if (isClassExpression(astNode.initializer)) {
          getClassProperties(astNode.initializer, currentPropsSet);
        }
      }
      nodeName = astNode.name?.getText();
    } else if (isInterfaceDeclaration(astNode)) {
      getInterfaceProperties(astNode, currentPropsSet);
    } else if (isTypeAliasDeclaration(astNode)) {
      getTypeAliasProperties(astNode, currentPropsSet);
    } else if (isElementAccessExpression(astNode)) {
      getElementAccessExpressionProperties(astNode, currentPropsSet);
    } else if (isObjectLiteralExpression(astNode)) {
      getObjectProperties(astNode, currentPropsSet);
    } else if (isClassExpression(astNode)) {
      getClassProperties(astNode, currentPropsSet);
    }

    if (nodeName && mCurrentExportNameSet.has(nodeName)) {
      addElement(currentPropsSet);
    } else if (isEnumDeclaration(astNode) && scanProjectConfig.isHarCompiled) {
      addElement(currentPropsSet);
    }
    forEachChild(astNode, visitProjectNode);
  };


  function addElement(currentPropsSet: Set<string>): void {
    currentPropsSet.forEach((element: string) => {
      mCurrentExportedPropertySet.add(element);
    });
    currentPropsSet.clear();
  }
  /**
   * parse file to api list and save to json object
   * @param fileName file name of api file
   * @param apiType
   * @private
   */
  const parseFile = function (fileName: string, apiType: ApiType): void {
    if (!FileUtils.isReadableFile(fileName) || !isParsableFile(fileName)) {
      return;
    }

    const sourceFile: SourceFile = createSourceFile(fileName, fs.readFileSync(fileName).toString(), ScriptTarget.ES2015, true);
    mCurrentExportedPropertySet.clear();
    // get export name list
    switch (apiType) {
      case ApiType.COMPONENT:
        forEachChild(sourceFile, visitChildNode);
        break;
      case ApiType.API:
        mCurrentExportNameSet.clear();
        forEachChild(sourceFile, visitExport);
        mCurrentExportNameSet.forEach(item => mSystemExportSet.add(item));

        forEachChild(sourceFile, visitPropertyAndName);
        mCurrentExportNameSet.clear();
        break;
      case ApiType.PROJECT_DEPENDS:
      case ApiType.PROJECT:
        mCurrentExportNameSet.clear();
        if (fileName.endsWith('.d.ts') || fileName.endsWith('.d.ets')) {
          forEachChild(sourceFile, visitChildNode);
        }

        forEachChild(sourceFile, visitProjectExport);
        forEachChild(sourceFile, visitProjectNode);
        mCurrentExportedPropertySet = handleWhiteListWhenExportObfs(fileName, mCurrentExportedPropertySet);
        break;
      case ApiType.CONSTRUCTOR_PROPERTY:
        forEachChild(sourceFile, visitNodeForConstructorProperty);
        break;
      default:
        break;
    }

    mCurrentExportNameSet.clear();
    mCurrentExportedPropertySet.forEach(item => mPropertySet.add(item));
    mCurrentExportedPropertySet.clear();
  };

  function handleWhiteListWhenExportObfs(fileName: string, mCurrentExportedPropertySet: Set<string>): Set<string> {
    // If mExportObfuscation is not enabled, collect the export names and their properties into the whitelist.
    if (!scanProjectConfig.mExportObfuscation) {
      return mCurrentExportedPropertySet;
    }
    // If the current file is a keep file or its dependent file, collect the export names and their properties into the whitelist.
    if (scanProjectConfig.mkeepFilesAndDependencies?.has(fileName)) {
      return mCurrentExportedPropertySet;
    }
    // If it is a project source code file, the names and their properties of the export will not be collected.
    if (!isRemoteHar(fileName)) {
      mCurrentExportedPropertySet.clear();
      return mCurrentExportedPropertySet;
    }
    // If it is a third-party library file, collect the export names.
    mCurrentExportNameSet.forEach((element) => {
      mLibExportNameSet.add(element);
    });
    return mCurrentExportedPropertySet;
  }

  const projectExtensions: string[] = ['.ets', '.ts', '.js'];
  const projectDependencyExtensions: string[] = ['.d.ets', '.d.ts', '.ets', '.ts', '.js'];
  const resolvedModules = new Set();

  function tryGetPackageID(filePath: string): string {
    const ohPackageJsonPath = path.join(filePath, 'oh-package.json5');
    let packgeNameAndVersion = '';
    if (fs.existsSync(ohPackageJsonPath)) {
      const ohPackageContent = json5.parse(fs.readFileSync(ohPackageJsonPath, 'utf-8'));
      packgeNameAndVersion = ohPackageContent.name + ohPackageContent.version;
    }
    return packgeNameAndVersion;
  }

  function traverseFilesInDir(apiPath: string, apiType: ApiType): void {
    let fileNames: string[] = fs.readdirSync(apiPath);
    for (let fileName of fileNames) {
      let filePath: string = path.join(apiPath, fileName);
      try {
        fs.accessSync(filePath, fs.constants.R_OK);
      } catch (err) {
        continue;
      }
      if (fs.statSync(filePath).isDirectory()) {
        const packgeNameAndVersion = tryGetPackageID(filePath);
        if (resolvedModules.has(packgeNameAndVersion)) {
          continue;
        }
        traverseApiFiles(filePath, apiType);
        packgeNameAndVersion.length > 0 && resolvedModules.add(packgeNameAndVersion);
        continue;
      }
      const suffix: string = path.extname(filePath);
      if ((apiType !== ApiType.PROJECT) && !projectDependencyExtensions.includes(suffix)) {
        continue;
      }

      if (apiType === ApiType.PROJECT && !projectExtensions.includes(suffix)) {
        continue;
      }
      parseFile(filePath, apiType);
    }
  }

  /**
   * traverse files of  api directory
   * @param apiPath api directory path
   * @param apiType
   * @private
   */
  export const traverseApiFiles = function (apiPath: string, apiType: ApiType): void {
    if (fs.statSync(apiPath).isDirectory()) {
      traverseFilesInDir(apiPath, apiType);
    } else {
      parseFile(apiPath, apiType);
    }
  };

  /**
   * desc: parse openHarmony sdk to get api list
   * @param version version of api, e.g. version 5.0.1.0 for api 9
   * @param sdkPath sdk real path of openHarmony
   * @param isEts true for ets, false for js
   * @param outputDir: sdk api output directory
   */
  export function parseOhSdk(sdkPath: string, version: string, isEts: boolean, outputDir: string): void {
    mPropertySet.clear();

    // visit api directory
    const apiPath: string = path.join(sdkPath, (isEts ? 'ets' : 'js'), version, 'api');
    traverseApiFiles(apiPath, ApiType.API);

    // visit component directory if ets
    if (isEts) {
      const componentPath: string = path.join(sdkPath, 'ets', version, 'component');
      traverseApiFiles(componentPath, ApiType.COMPONENT);
    }

    // visit the UI conversion API
    const uiConversionPath: string = path.join(sdkPath, (isEts ? 'ets' : 'js'), version,
      'build-tools', 'ets-loader', 'lib', 'pre_define.js');
    extractStringsFromFile(uiConversionPath);

    const reservedProperties: string[] = [...mPropertySet.values()];
    mPropertySet.clear();

    writeToFile(reservedProperties, path.join(outputDir, 'propertiesReserved.json'));
  }

  export function extractStringsFromFile(filePath: string): void {
    let collections: string[] = [];
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    const regex = /"([^"]*)"/g;
    const matches = fileContent.match(regex);

    if (matches) {
      collections = matches.map(match => match.slice(1, -1));
    }

    collections.forEach(name => mPropertySet.add(name));
  }

  /**
   * parse common project or file to extract exported api list
   * @return reserved api names
   */
  export function parseCommonProject(projectPath: string, customProfiles: IOptions, scanningApiType: ApiType): string[] {
    mPropertySet.clear();
    if (fs.lstatSync(projectPath).isFile()) {
      if (projectPath.endsWith('.ets') || projectPath.endsWith('.ts') || projectPath.endsWith('.js')) {
        parseFile(projectPath, scanningApiType);
      }
    } else {
      traverseApiFiles(projectPath, scanningApiType);
    }

    let reservedProperties: string[] = [...mPropertySet];
    mPropertySet.clear();
    return reservedProperties;
  }

  /**
   * parse api of third party libs like libs in node_modules
   * @param libPath
   */
  export function parseThirdPartyLibs(libPath: string, scanningApiType: ApiType): {reservedProperties: string[]; reservedLibExportNames: string[] | undefined} {
    mPropertySet.clear();
    mLibExportNameSet.clear();
    if (fs.lstatSync(libPath).isFile()) {
      if (libPath.endsWith('.ets') || libPath.endsWith('.ts') || libPath.endsWith('.js')) {
        parseFile(libPath, scanningApiType);
      }
    } else {
      const filesAndfolders = fs.readdirSync(libPath);
      for (let subPath of filesAndfolders) {
        traverseApiFiles(path.join(libPath, subPath), scanningApiType);
      }
    }
    let reservedLibExportNames: string[] = undefined;
    if (scanProjectConfig.mExportObfuscation) {
      reservedLibExportNames = [...mLibExportNameSet];
      mLibExportNameSet.clear();
    }
    const reservedProperties: string[] = [...mPropertySet];
    mPropertySet.clear();

    return {reservedProperties: reservedProperties, reservedLibExportNames: reservedLibExportNames};
  }

  /**
   * save api json object to file
   * @private
   */
  export function writeToFile(reservedProperties: string[], outputPath: string): void {
    let str: string = JSON.stringify(reservedProperties, null, '\t');
    fs.writeFileSync(outputPath, str);
  }

  export function isRemoteHar(filePath: string): boolean {
    const realPath: string = sys.realpath(filePath);
    return isInOhModuleFile(realPath);
  }
  
  export function isInOhModuleFile(filePath: string): boolean {
    return filePath.indexOf('/oh_modules/') !== -1 || filePath.indexOf('\\oh_modules\\') !== -1;
  }

  export function isParsableFile(path: string): boolean {
    return supportedParsingExtension.some(extension => path.endsWith(extension));
  }

   /**
   * parse common project or file to extract exported api list
   * @return reserved api names
   */
   export function parseProjectSourceByPaths(projectPaths: string[], customProfiles: IOptions, scanningApiType: ApiType): string[] {
    mPropertySet.clear();
    projectPaths.forEach(path => {
      parseFile(path, scanningApiType);
    })
    let reservedProperties: string[] = [...mPropertySet];
    mPropertySet.clear();
    return reservedProperties;
  }

  /**
   * parse api of third party libs like libs in node_modules
   * @param libPath
   */
  export function parseThirdPartyLibsByPaths(libPaths: string[], scanningApiType: ApiType): {reservedProperties: string[];
    reservedLibExportNames: string[] | undefined} {
    mPropertySet.clear();
    mLibExportNameSet.clear();
    libPaths.forEach(path => {
      parseFile(path, scanningApiType);
    })
    let reservedLibExportNames: string[] = undefined;
    if (scanProjectConfig.mExportObfuscation) {
      reservedLibExportNames = [...mLibExportNameSet];
      mLibExportNameSet.clear();
    }
    const reservedProperties: string[] = [...mPropertySet];
    mPropertySet.clear();

    return {reservedProperties: reservedProperties, reservedLibExportNames: reservedLibExportNames};
  }
}
