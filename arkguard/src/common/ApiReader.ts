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
import {ApiExtractor} from './ApiExtractor';
import {ListUtil} from '../utils/ListUtil';
import type {IOptions} from '../configs/IOptions';
import { stringPropsSet, structPropsSet, enumPropsSet } from '../utils/OhsUtil';

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

function initScanProjectConfig(customProfiles: IOptions, isHarCompiled?: boolean): void {
  scanProjectConfig.mPropertyObfuscation = customProfiles.mNameObfuscation?.mRenameProperties;
  scanProjectConfig.mKeepStringProperty = customProfiles.mNameObfuscation?.mKeepStringProperty;
  scanProjectConfig.mExportObfuscation = customProfiles.mExportObfuscation;
  scanProjectConfig.mkeepFilesAndDependencies = customProfiles.mKeepFileSourceCode?.mkeepFilesAndDependencies;
  scanProjectConfig.isHarCompiled = isHarCompiled;
}

export interface ReseverdSetForArkguard {
  structPropertySet: Set<string> | undefined;
  stringPropertySet: Set<string> | undefined;
  exportNameAndPropSet: Set<string> | undefined;
  exportNameSet: Set<string> | undefined;
  enumPropertySet: Set<string> | undefined;
}

/**
 * read project reserved properties by collected paths
 * @param filesForCompilation set collection of files
 * @param customProfiles
 */
export function readProjectPropertiesByCollectedPaths(filesForCompilation: Set<string>,
  customProfiles: IOptions, isHarCompiled: boolean): ReseverdSetForArkguard {
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
  const exportNamesAndProperties: Set<string> | undefined = exportWhiteList.reservedExportPropertyAndName;
  const exportNames: Set<string> | undefined = exportWhiteList.reservedExportNames;

  // if -enable-property-obfuscation, collect structPropsSet, exportNamesAndProperties and
  // stringPropsSet(if -enable-string-property-obufscation is not enabled) as whitelists.
  let exportNameAndPropSet: Set<string>;
  let structPropertySet: Set<string>;
  let stringPropertySet: Set<string>;
  let enumPropertySet: Set<string>;
  if (isEnabledPropertyObfuscation(customProfiles)) {
    exportNameAndPropSet = new Set(exportNamesAndProperties);
    structPropertySet = new Set(structPropsSet);
    enumPropertySet = new Set(enumPropsSet);
    if (scanProjectConfig.mKeepStringProperty) {
      stringPropertySet = new Set(stringPropsSet);
    }
  }
  structPropsSet.clear();
  stringPropsSet.clear();
  enumPropsSet.clear();

  let exportNameSet: Set<string>;
  if (scanProjectConfig.mExportObfuscation) {
    exportNameSet = new Set(exportNames);
  }

  // scanProjectConfig needs to be cleared to prevent affecting incremental compilation
  scanProjectConfig = {};

  return {
    structPropertySet: structPropertySet,
    stringPropertySet: stringPropertySet,
    exportNameAndPropSet: exportNameAndPropSet,
    exportNameSet: exportNameSet,
    enumPropertySet: enumPropertySet,
  };
}
