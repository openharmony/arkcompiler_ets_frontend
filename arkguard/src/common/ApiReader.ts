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
import es6Info from '../configs/preset/es6_reserved_properties.json';


export const scanProjectConfig: {mKeepStringProperty?: boolean} = {};

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
  return customProfiles.mNameObfuscation &&
    customProfiles.mNameObfuscation.mEnable &&
    customProfiles.mNameObfuscation.mRenameProperties;
}

/**
 * read project reserved properties
 * @param projectPaths can be dir or file
 * @param customProfiles
 */
export function readProjectProperties(projectPaths: string[], customProfiles: IOptions, isOHProject?: boolean): string[] {
  if (!needReadApiInfo(customProfiles) && !isOHProject) {
    return [];
  }

  scanProjectConfig.mKeepStringProperty = customProfiles.mNameObfuscation?.mKeepStringProperty;

  for (const projectPath of projectPaths) {
    if (!fs.existsSync(projectPath)) {
      console.error(`File ${FileUtils.getFileName(projectPath)} is not found.`);
      return [];
    }

    const sourcPath = isOHProject ? path.join(projectPath, 'src', 'main') : projectPath;
    const projProperties: string[] = ApiExtractor.parseCommonProject(sourcPath);
    const sdkProperties: string[] = readThirdPartyLibProperties(projectPath);

    // read project code export names
    customProfiles.mNameObfuscation.mReservedProperties = ListUtil.uniqueMergeList(projProperties,
      customProfiles.mNameObfuscation.mReservedProperties);

    // read project lib export names
    if (sdkProperties) {
      customProfiles.mNameObfuscation.mReservedProperties = ListUtil.uniqueMergeList(sdkProperties,
        customProfiles.mNameObfuscation.mReservedProperties);
    }
  }
  return customProfiles.mNameObfuscation.mReservedProperties;
}

function readThirdPartyLibProperties(projectPath: string): string[] {
  let reservedProperties: string[] = [];

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

  const properties: string[] = ApiExtractor.parseThirdPartyLibs(filePath);
  reservedProperties = [...reservedProperties, ...properties];
  const propertySet: Set<string> = new Set<string>(reservedProperties);

  return Array.from(propertySet);
}
