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

import path from 'path';
import fs from 'fs';
import {FileUtils} from '../utils/FileUtils';
import {ApiExtractor} from './ApiExtractor';
import {ListUtil} from '../utils/ListUtil';
import type {IOptions} from '../configs/IOptions';
import { stringPropsSet, structPropsSet, enumPropsSet } from '../utils/OhsUtil';
import { INameObfuscationOption } from '../configs/INameObfuscationOption';

export let scanProjectConfig: {
  mPropertyObfuscation?: boolean,
  mKeepStringProperty?: boolean,
  mExportObfuscation?: boolean,
  mkeepFilesAndDependencies?: Set<string>,
  isHarCompiled?: boolean
} = {};

/**
 * if rename property is not open, api read and extract can be skipped
 *
 * init plugin, read api info of openHarmony sdk and generate file of reserved name, property and string.
 * @param sdkDir absolute path like D:\\HuaweiApp\\ohsdk
 * @param outputDir
 */
export function initPlugin(sdkDir: string, outputDir: string): void {
  // create sdk api file if not exist
  const ohSdkPath: string = path.resolve(sdkDir);
  if (!ohSdkPath) {
    console.error('SDK path is not found.');
  }

  const apiVersions: string[] = [''];

  apiVersions.forEach((versionString) => {
    ApiExtractor.parseOhSdk(ohSdkPath, versionString, true, outputDir);
  });
}

/**
 * need read api info or not
 * @param customProfiles
 */
export function needReadApiInfo(customProfiles: IOptions): boolean {
  return isEnabledPropertyObfuscation(customProfiles) || customProfiles.mExportObfuscation;
}

export function isEnabledPropertyObfuscation(customProfiles: IOptions): boolean {
  return (customProfiles.mNameObfuscation &&
    customProfiles.mNameObfuscation.mEnable &&
    customProfiles.mNameObfuscation.mRenameProperties);
}

/**
 * read project reserved properties for UT
 * @param projectPaths can be dir or file
 * @param customProfiles
 */
export function readProjectProperties(projectPaths: string[], customProfiles: IOptions, isOHProject?: boolean):
  {projectAndLibsReservedProperties: string[]; libExportNames: string[]} {

  let scanningCommonType: ApiExtractor.ApiType = undefined;
  let scanningLibsType: ApiExtractor.ApiType = undefined;
  if (isEnabledPropertyObfuscation(customProfiles)) {
    scanningCommonType = ApiExtractor.ApiType.PROJECT;
    scanningLibsType = ApiExtractor.ApiType.PROJECT_DEPENDS;
  } else {
    scanningCommonType = ApiExtractor.ApiType.CONSTRUCTOR_PROPERTY;
    scanningLibsType = ApiExtractor.ApiType.CONSTRUCTOR_PROPERTY;
  }
  ApiExtractor.mConstructorPropertySet = new Set();
  // This call is for UT.
  initScanProjectConfig(customProfiles);

  for (const projectPath of projectPaths) {
    if (!fs.existsSync(projectPath)) {
      console.error(`File ${FileUtils.getFileName(projectPath)} is not found.`);
      return {projectAndLibsReservedProperties:[], libExportNames: []};
    }
    stringPropsSet.clear();
    const sourcPath = isOHProject ? path.join(projectPath, 'src', 'main') : projectPath;
    const projProperties: string[] = ApiExtractor.parseCommonProject(sourcPath, customProfiles, scanningCommonType);
    const libExportNamesAndReservedProps = readThirdPartyLibProperties(projectPath, scanningLibsType);
    const sdkProperties = libExportNamesAndReservedProps?.reservedProperties;

    if (isEnabledPropertyObfuscation(customProfiles)) {
      // read project code export names
      customProfiles.mNameObfuscation.mReservedProperties = ListUtil.uniqueMergeList(projProperties,
        customProfiles.mNameObfuscation.mReservedProperties, [...structPropsSet]);

      // read project lib export names
      if (sdkProperties && sdkProperties.length > 0) {
        customProfiles.mNameObfuscation.mReservedProperties = ListUtil.uniqueMergeList(sdkProperties,
          customProfiles.mNameObfuscation.mReservedProperties);
      }

      if (scanProjectConfig.mKeepStringProperty && stringPropsSet.size > 0) {
        customProfiles.mNameObfuscation.mReservedProperties = ListUtil.uniqueMergeList([...stringPropsSet],
          customProfiles.mNameObfuscation.mReservedProperties);
      }
    }
    structPropsSet.clear();
    stringPropsSet.clear();
    if (scanProjectConfig.mExportObfuscation && libExportNamesAndReservedProps?.reservedLibExportNames) {
      customProfiles.mNameObfuscation.mReservedNames = ListUtil.uniqueMergeList(libExportNamesAndReservedProps.reservedLibExportNames,
        customProfiles.mNameObfuscation.mReservedNames);
    }
  }

  return {
    projectAndLibsReservedProperties: customProfiles.mNameObfuscation.mReservedProperties ?? [],
    libExportNames: customProfiles.mNameObfuscation.mReservedNames ?? []
  };
}

function initScanProjectConfig(customProfiles: IOptions, isHarCompiled?: boolean): void {
  scanProjectConfig.mPropertyObfuscation = customProfiles.mNameObfuscation?.mRenameProperties;
  scanProjectConfig.mKeepStringProperty = customProfiles.mNameObfuscation?.mKeepStringProperty;
  scanProjectConfig.mExportObfuscation = customProfiles.mExportObfuscation;
  scanProjectConfig.mkeepFilesAndDependencies = customProfiles.mKeepFileSourceCode?.mkeepFilesAndDependencies;
  scanProjectConfig.isHarCompiled = isHarCompiled;
}
/**
 * read project reserved properties by collected paths
 * @param filesForCompilation set collection of files
 * @param customProfiles
 */
export function readProjectPropertiesByCollectedPaths(filesForCompilation: Set<string>, customProfiles: IOptions, isHarCompiled: boolean): {
  projectAndLibsReservedProperties: string[];
  libExportNames: string[]} {
  const apiType = ApiExtractor.ApiType;
  let scanningCommonType = undefined;
  let scanningLibsType = undefined;
  if (needReadApiInfo(customProfiles)) {
    scanningCommonType = apiType.PROJECT;
    scanningLibsType = apiType.PROJECT_DEPENDS;
  } else {
    scanningCommonType = apiType.CONSTRUCTOR_PROPERTY;
    scanningLibsType = apiType.CONSTRUCTOR_PROPERTY;
  }
  // The purpose of collecting constructor properties is to avoid generating the same name as the constructor property when obfuscating identifier names.
  ApiExtractor.mConstructorPropertySet = new Set();

  initScanProjectConfig(customProfiles, isHarCompiled);

  stringPropsSet.clear();

  const exportWhiteList = ApiExtractor.parseFileByPaths(filesForCompilation, scanningCommonType);
  const exportNamesAndProperties: string[] = exportWhiteList.reservedProperties;
  const exportNames: string[] = exportWhiteList.reservedExportNames;

  const nameObfuscationConfig = customProfiles.mNameObfuscation;
  if (isEnabledPropertyObfuscation(customProfiles)) {
    mergeReservedProperties(nameObfuscationConfig, exportNamesAndProperties);
  }
  structPropsSet.clear();
  stringPropsSet.clear();
  enumPropsSet.clear();

  if (scanProjectConfig.mExportObfuscation) {
    mergeReservedNames(nameObfuscationConfig, exportNames);
  }

  // scanProjectConfig needs to be cleared to prevent affecting incremental compilation
  scanProjectConfig = {};

  return {
    projectAndLibsReservedProperties: nameObfuscationConfig.mReservedProperties ?? [],
    libExportNames: nameObfuscationConfig.mReservedNames ?? []
  };
}

function mergeReservedProperties(nameObfuscationConfig: INameObfuscationOption, exportNamesAndProperties: string[]): void {
  if (exportNamesAndProperties.length > 0) {
    nameObfuscationConfig.mReservedProperties = ListUtil.uniqueMergeList(exportNamesAndProperties, nameObfuscationConfig.mReservedProperties);
  }

  if (scanProjectConfig.mKeepStringProperty && stringPropsSet.size > 0) {
    nameObfuscationConfig.mReservedProperties = ListUtil.uniqueMergeList([...stringPropsSet], nameObfuscationConfig.mReservedProperties);
  }

  if (enumPropsSet.size > 0) {
    nameObfuscationConfig.mReservedProperties = ListUtil.uniqueMergeList([...enumPropsSet], nameObfuscationConfig.mReservedProperties);
  }

  if (structPropsSet.size > 0) {
    nameObfuscationConfig.mReservedProperties = ListUtil.uniqueMergeList([...structPropsSet], nameObfuscationConfig.mReservedProperties);
  }
}

function mergeReservedNames(nameObfuscationConfig: INameObfuscationOption, exportNames: string[]): void {
  if (exportNames.length > 0) {
    nameObfuscationConfig.mReservedNames = ListUtil.uniqueMergeList(exportNames, nameObfuscationConfig.mReservedNames);
  }
}

function readThirdPartyLibProperties(projectPath: string, scanningApiType: ApiExtractor.ApiType): {reservedProperties: string[];
  reservedLibExportNames: string[] | undefined} {
  if (!fs.lstatSync(projectPath).isDirectory()) {
    return undefined;
  }

  // find third party lib and extract reserved names
  const fileNames: string[] = fs.readdirSync(projectPath);
  const hasNodeModules: boolean = fileNames.includes('node_modules');
  const hasOHModules: boolean = fileNames.includes('oh_modules');
  if (!hasNodeModules && !hasOHModules) {
    return undefined;
  }
  if (hasNodeModules && hasOHModules) {
    throw new Error(`There are both node_modules and oh_modules folders in ${projectPath}`);
  }

  let filePath: string = '';
  if (hasNodeModules) {
    filePath = path.join(projectPath, 'node_modules');
  } else {
    filePath = path.join(projectPath, 'oh_modules');
  }

  return ApiExtractor.parseThirdPartyLibs(filePath, scanningApiType);
}
