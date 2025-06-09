/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
  ObConfigResolver,
  SourceObConfig,
} from '../../../src/initialization/ConfigResolver';

import { HvigorErrorInfo, PropCollections, renameFileNameModule } from '../../../src/ArkObfuscator';

import { describe, it } from 'mocha';
import { expect } from 'chai';
import path from 'path';
import fs from 'fs';
import exp from 'constants';

function printObfLogger(errorInfo: string, errorCodeInfo: HvigorErrorInfo | string, level: string): void {
  switch (level) {
    case 'warn':
      console.warn(errorInfo);
      break;
    case 'error':
      console.error(errorInfo);
      break;
    default:
      break;
  }
}

describe('hsp support consumerFiles', () => {
  describe('hsp config resolver',() => {
    let hapConfig: SourceObConfig;
    let localHspConfig: SourceObConfig;
    let remoteHspConfig: SourceObConfig;
    let remoteHarConfig: SourceObConfig;
    let localHarConfig: SourceObConfig;
    let localMainHspConfig: SourceObConfig;
    let remoteMainHspConfig: SourceObConfig;
    let libTestHapConfig: SourceObConfig;
    const hapRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/Hap/obfuscation-rules.txt');
    const outputDir = path.join(__dirname, '../../testData/output');
    const localHspRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/localHsp/obfuscation-rules.txt');
    const localHspExportRulePathFile = path.join(__dirname, '../../testData/output/localHsp_obfuscation.txt');
    const localHspConsumerRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/localHsp/consumer-rules.txt');
    const remoteHspRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteHsp/obfuscation-rules.txt');
    const remoteHspConsumerRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteHsp/consumer-rules.txt');
    const remoteHspExportRulePathFile = path.join(__dirname, '../../testData/output/remoteHsp_obfuscation.txt');
    const remoteHspObfFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteHsp/obfuscation.txt');
    const localHarRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/localHar/obfuscation-rules.txt');
    const localHarConsumerRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/localHar/consumer-rules.txt');
    const localHarExportRulePathFile = path.join(__dirname, '../../testData/output/localHar_obfuscation.txt');
    const remoteHarRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteHar/obfuscation-rules.txt');
    const remoteHarConsumerRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteHar/consumer-rules.txt');
    const remoteHarExportRulePathFile = path.join(__dirname, '../../testData/output/remoteHar_obfuscation.txt');
    const remoteHarObfFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteHar/obfuscation.txt');
    const remoteHarDependsLocalHspObfFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteHar/obfuscationDependLocalHsp.txt');
    const remoteHarDependsRemoteHspObfFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteHar/obfuscationDependRemoteHsp.txt');
    const localMainHspRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/localMainHsp/obfuscation-rules.txt');
    const localMainHspConsumerRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/localMainHsp/consumer-rules.txt');
    const localMainHspExportRulePathFile = path.join(__dirname, '../../testData/output/localMainHsp_obfuscation.txt');
    const remoteMainHspRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteMainHsp/obfuscation-rules.txt');
    const remoteMainHspConsumerRulesFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteMainHsp/consumer-rules.txt');
    const remoteMainHspExportRulePathFile = path.join(__dirname, '../../testData/output/remoteMainHsp_obfuscation.txt');
    const remoteMainHspObfFile = path.join(__dirname, '../../testData/obfuscation/Configs/remoteMainHsp/obfuscation.txt');
    const systemApiCacheFile = path.join(__dirname, '../../testData/output/systemApiCache.json');
    const libTestHapRulesFile = path.join(
      __dirname,
      '../../testData/obfuscation/Configs/Hap/obfuscation-rules-lib-test.txt',
    );
    isConfigFileExist(remoteHarObfFile);
    isConfigFileExist(hapRulesFile);
    isConfigFileExist(localHspRulesFile);
    isConfigFileExist(localHspConsumerRulesFile);
    isConfigFileExist(remoteHspRulesFile);
    isConfigFileExist(remoteHspConsumerRulesFile);
    isConfigFileExist(localHarRulesFile);
    isConfigFileExist(localHarConsumerRulesFile);
    isConfigFileExist(remoteHarRulesFile);
    isConfigFileExist(remoteHarConsumerRulesFile);
    isConfigFileExist(localMainHspRulesFile);
    isConfigFileExist(localMainHspConsumerRulesFile);
    isConfigFileExist(remoteMainHspRulesFile);
    isConfigFileExist(remoteMainHspConsumerRulesFile);
    isConfigFileExist(remoteMainHspObfFile);
    isConfigFileExist(remoteHarObfFile);
    isConfigFileExist(remoteHarDependsLocalHspObfFile);
    isConfigFileExist(remoteHarDependsRemoteHspObfFile);
    isConfigFileExist(remoteHspObfFile);

    function initModulesConfig(): void {
      hapConfig = {
        selfConfig: {
          ruleOptions: {
            enable: true,
            rules: [hapRulesFile]
          },
          consumerRules: [],
          libDir: "",
          consumerFiles: ""
        },
        dependencies: {
          libraries: [],
          hars: [],
          hsps: [],
          hspLibraries: []
        },
        sdkApis: [],
        obfuscationCacheDir: outputDir,
        exportRulePath: ''
      };
      localHspConfig = {
        selfConfig: {
          ruleOptions: {
            enable: true,
            rules: [localHspRulesFile]
          },
          consumerRules: [localHspConsumerRulesFile],
          libDir: "",
          consumerFiles: ""
        },
        dependencies: { libraries: [], hars: [], hsps: [], hspLibraries: [] },
        sdkApis: [],
        obfuscationCacheDir: outputDir,
        exportRulePath: localHspExportRulePathFile
      };
      remoteHspConfig = {
        selfConfig: {
          ruleOptions: {
            enable: true,
            rules: [remoteHspRulesFile]
          },
          consumerRules: [remoteHspConsumerRulesFile],
          libDir: "",
          consumerFiles: ""
        },
        dependencies: { libraries: [], hars: [], hsps: [], hspLibraries: [] },
        sdkApis: [],
        obfuscationCacheDir: outputDir,
        exportRulePath: remoteHspExportRulePathFile
      };
      remoteHarConfig = {
        selfConfig: {
          ruleOptions: {
            enable: true,
            rules: [remoteHarRulesFile]
          },
          consumerRules: [remoteHarConsumerRulesFile],
          libDir: "",
          consumerFiles: ""
        },
        dependencies: { libraries: [], hars: [], hsps: [], hspLibraries: [] },
        sdkApis: [],
        obfuscationCacheDir: outputDir,
        exportRulePath: remoteHarExportRulePathFile
      };
      localHarConfig= {
        selfConfig: {
          ruleOptions: {
            enable: true,
            rules: [localHarRulesFile]
          },
          consumerRules: [localHarConsumerRulesFile],
          libDir: "",
          consumerFiles: ""
        },
        dependencies: { libraries: [], hars: [], hsps: [], hspLibraries: [] },
        sdkApis: [],
        obfuscationCacheDir: outputDir,
        exportRulePath: localHarExportRulePathFile
      };
      localMainHspConfig = {
        selfConfig: {
          ruleOptions: {
            enable: true,
            rules: [localMainHspRulesFile]
          },
          consumerRules: [localMainHspConsumerRulesFile],
          libDir: "",
          consumerFiles: ""
        },
        dependencies: {
          libraries: [],
          hars: [],
          hsps: [],
          hspLibraries: []
        },
        sdkApis: [],
        obfuscationCacheDir: outputDir,
        exportRulePath: localMainHspExportRulePathFile
      };
      remoteMainHspConfig = {
        selfConfig: {
          ruleOptions: {
            enable: true,
            rules: [remoteMainHspRulesFile]
          },
          consumerRules: [remoteMainHspConsumerRulesFile],
          libDir: "",
          consumerFiles: ""
        },
        dependencies: {
          libraries: [],
          hars: [],
          hsps: [],
          hspLibraries: []
        },
        sdkApis: [],
        obfuscationCacheDir: outputDir,
        exportRulePath: remoteMainHspExportRulePathFile
      };
      libTestHapConfig = {
        selfConfig: {
          ruleOptions: {
            enable: true,
            rules: [libTestHapRulesFile],
          },
          consumerRules: [],
          libDir: '',
          consumerFiles: '',
        },
        dependencies: {
          libraries: [],
          hars: [],
          hsps: [],
          hspLibraries: [],
        },
        sdkApis: [],
        obfuscationCacheDir: outputDir,
        exportRulePath: '',
      };
    }

    function isConfigFileExist(filePath: string): void {
      if(!fs.existsSync(filePath)){
        throw new Error(`${filePath} does not exist`);
      }
    }

    describe('getDependencyConfigs with hsps and hspLibrarys', ()=> {
      describe('HSP Depends on Har Tests', function () {
        before(async () => {
          initModulesConfig(); 
        });
        
        it('should include only HSP consumerFiles rules in HSP obfuscation.txt', function () {
          localHspConfig.dependencies.libraries.push(localHarConfig.selfConfig);
          localHspConfig.dependencies.hars.push(remoteHarObfFile);  
          const hspResolver = new ObConfigResolver({ obfuscationOptions: localHspConfig, compileHar: false, compileShared: true }, printObfLogger);
          hspResolver.resolveObfuscationConfigs();
          hspResolver.emitConsumerConfigFiles();

          const hspObfuscationContent = fs.readFileSync(localHspConfig.exportRulePath, 'utf-8');  
          expect(hspObfuscationContent).not.to.include('-disable-obfuscation');
          expect(hspObfuscationContent).to.include('-enable-toplevel-obfuscation');
          expect(hspObfuscationContent).not.to.include('-enable-property-obfuscation');
          expect(hspObfuscationContent).not.to.include('-enable-string-property-obfuscation');
          expect(hspObfuscationContent).not.to.include('-enable-filename-obfuscation');
          expect(hspObfuscationContent).not.to.include('-enable-export-obfuscation');
          expect(hspObfuscationContent).not.to.include('-remove-comments');
          expect(hspObfuscationContent).not.to.include('-compact');
          expect(hspObfuscationContent).not.to.include('-remove-log');

          expect(hspObfuscationContent).not.to.include('-keep-dts');
          expect(hspObfuscationContent).to.include('-keep-global-name');
          expect(hspObfuscationContent).to.include('-keep-property-name');
          expect(hspObfuscationContent).not.to.include('-keep-file-name');
          expect(hspObfuscationContent).not.to.include('-keep-comments');

          expect(hspObfuscationContent).to.include('localHspMethod');
          expect(hspObfuscationContent).to.include('LocalHspClass');
          expect(hspObfuscationContent).not.to.include('LocalHarClass');
          expect(hspObfuscationContent).not.to.include('localHarMethod');
          expect(hspObfuscationContent).not.to.include('RemoteHarClass');
          expect(hspObfuscationContent).not.to.include('remoteHarMethod');
        });

        it('should merge HAR and HSP consumer rules for HAP when HAP depends on localHsp and localHsp depends on localHar', function () {
          hapConfig.dependencies.hspLibraries?.push(localHspConfig.selfConfig);
          const configResolver = new ObConfigResolver({ obfuscationOptions: hapConfig, compileHar: false, compileShared: false }, printObfLogger);
          const finalConfig = configResolver.resolveObfuscationConfigs();
          expect(finalConfig.options.enableToplevelObfuscation).to.be.false;
          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.false;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;
          expect(finalConfig.options.compact).to.be.false;
          expect(finalConfig.options.removeLog).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('LocalHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHspMethod');
          expect(finalConfig.reservedGlobalNames).not.to.include('LocalHarClass');
          expect(finalConfig.reservedPropertyNames).not.to.include('localHarMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });
        
        afterEach(() => {
          if (fs.existsSync(localHspConfig.exportRulePath)) {
            fs.unlinkSync(localHspConfig.exportRulePath);
          }
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      });

      describe('localHAR depends on localHSP Tests', function () {
        before(async () => {
          initModulesConfig();
        });

        it('should merge both HSP and HAR consumer rules in HAR obfuscation.txt', function () {
          localHarConfig.dependencies.hspLibraries?.push(localHspConfig.selfConfig);
          const localHarResolver = new ObConfigResolver({ obfuscationOptions: localHarConfig, compileHar: true, compileShared: false }, printObfLogger);
          localHarResolver.resolveObfuscationConfigs();
          localHarResolver.emitConsumerConfigFiles();

          const localHarObfuscationContent = fs.readFileSync(localHarConfig.exportRulePath, 'utf-8');

          expect(localHarObfuscationContent).to.include('-enable-toplevel-obfuscation');
          expect(localHarObfuscationContent).to.include('-enable-property-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-enable-string-property-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-enable-filename-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-enable-export-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-remove-comments');
          expect(localHarObfuscationContent).not.to.include('-compact');
          expect(localHarObfuscationContent).not.to.include('-remove-log');
          
          expect(localHarObfuscationContent).to.include('-keep-global-name');
          expect(localHarObfuscationContent).to.include('-keep-property-name');
          expect(localHarObfuscationContent).not.to.include('-keep-file-name');
          expect(localHarObfuscationContent).not.to.include('-keep-comments');
          expect(localHarObfuscationContent).not.to.include('-keep-dts');

          expect(localHarObfuscationContent).to.include('LocalHspClass');
          expect(localHarObfuscationContent).to.include('localHspMethod');
          expect(localHarObfuscationContent).to.include('LocalHarClass');
          expect(localHarObfuscationContent).to.include('localHarMethod');
        });

        it('should merge HAR consumer rules for HAP when HAP depends on localHar and localHar depends on localHsp', function () {
          hapConfig.dependencies.libraries.push(localHarConfig.selfConfig);
          hapConfig.dependencies.hspLibraries?.push(localHspConfig.selfConfig);  
          const configResolver = new ObConfigResolver({ obfuscationOptions: hapConfig, compileHar: false, compileShared: false }, printObfLogger);
          const finalConfig = configResolver.resolveObfuscationConfigs();

          expect(finalConfig.options.enableToplevelObfuscation).to.be.false;
          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.false;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;
          expect(finalConfig.options.compact).to.be.false;
          expect(finalConfig.options.removeLog).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('LocalHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHarMethod');
          expect(finalConfig.reservedGlobalNames).to.include('LocalHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHarMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });

        afterEach(() => {
          if (fs.existsSync(localHspConfig.exportRulePath)) {
            fs.unlinkSync(localHspConfig.exportRulePath);
          }
          if (fs.existsSync(localHarConfig.exportRulePath)) {
            fs.unlinkSync(localHarConfig.exportRulePath);
          }
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      });
    
      describe('localHAR depends on remoteHSP Tests', function () {
        before(async () => {
          initModulesConfig();
        });

        it('should merge both HSP obfuscation.txt and HAR consumer rules in HAR obfuscation.txt', function () {
          localHarConfig.dependencies.hsps?.push(remoteHspObfFile);
          const localHarResolver = new ObConfigResolver({ obfuscationOptions: localHarConfig, compileHar: true, compileShared: false }, printObfLogger);
          localHarResolver.resolveObfuscationConfigs();
          localHarResolver.emitConsumerConfigFiles();

          const localHarObfuscationContent = fs.readFileSync(localHarConfig.exportRulePath, 'utf-8');

          expect(localHarObfuscationContent).to.include('-remove-log');
          expect(localHarObfuscationContent).to.include('-enable-property-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-enable-toplevel-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-enable-string-property-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-enable-filename-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-enable-export-obfuscation');
          expect(localHarObfuscationContent).not.to.include('-remove-comments');
          expect(localHarObfuscationContent).not.to.include('-compact');
          
          expect(localHarObfuscationContent).to.include('-keep-global-name');
          expect(localHarObfuscationContent).to.include('-keep-property-name');
          expect(localHarObfuscationContent).not.to.include('-keep-file-name');
          expect(localHarObfuscationContent).not.to.include('-keep-comments');
          expect(localHarObfuscationContent).not.to.include('-keep-dts');

          expect(localHarObfuscationContent).to.include('RemoteHspClass');
          expect(localHarObfuscationContent).to.include('remoteHspMethod');
          expect(localHarObfuscationContent).to.include('LocalHarClass');
          expect(localHarObfuscationContent).to.include('localHarMethod');
        });

        it('should merge HAR consumer rules for HAP when HAP depends on localHar and localHar depends on remoteHsp', function () {
          hapConfig.dependencies.libraries.push(localHarConfig.selfConfig);
          hapConfig.dependencies.hsps?.push(remoteHspObfFile);
          const configResolver = new ObConfigResolver({ obfuscationOptions: hapConfig, compileHar: false, compileShared: false }, printObfLogger);
          const finalConfig = configResolver.resolveObfuscationConfigs();

          expect(finalConfig.options.removeLog).to.be.false;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.false;
          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.enableToplevelObfuscation).to.be.false;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;
          expect(finalConfig.options.compact).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('LocalHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHarMethod');
          expect(finalConfig.reservedGlobalNames).to.include('RemoteHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteHspMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });

        afterEach(() => {
          if (fs.existsSync(remoteHspConfig.exportRulePath)) {
            fs.unlinkSync(remoteHspConfig.exportRulePath);
          }
          if (fs.existsSync(localHarConfig.exportRulePath)) {
            fs.unlinkSync(localHarConfig.exportRulePath);
          }
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      });

      describe('remoteHAR depends on localHSP Tests', function () {
        before(async () => {
          initModulesConfig();
        });

        it('should retain HAR consumer rules for HAP when HAP depends on remoteHar and remoteHar depends on localHsp', function () {
          hapConfig.dependencies.hars.push(remoteHarDependsLocalHspObfFile);
          const configResolver = new ObConfigResolver({ obfuscationOptions: hapConfig, compileHar: false, compileShared: false }, printObfLogger);
          const finalConfig = configResolver.resolveObfuscationConfigs();

          expect(finalConfig.options.compact).to.be.false;
          expect(finalConfig.options.enableToplevelObfuscation).to.be.false;
          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.removeLog).to.be.false;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.false;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('RemoteHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteHarMethod');
          expect(finalConfig.reservedGlobalNames).to.include('LocalHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHspMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });

        afterEach(() => {
          if (fs.existsSync(localHspConfig.exportRulePath)) {
            fs.unlinkSync(localHspConfig.exportRulePath);
          }
          if (fs.existsSync(remoteHarConfig.exportRulePath)) {
            fs.unlinkSync(remoteHarConfig.exportRulePath);
          }
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      });

      describe('remoteHAR depends on remoteHSP Tests', function () {
        before(async () => {
          initModulesConfig();
        });

        it('should retain HAR consumer rules for HAP when HAP depends on remoteHar and remoteHar depends on remoteHsp', function () {
          hapConfig.dependencies.hars.push(remoteHarDependsRemoteHspObfFile);
          const configResolver = new ObConfigResolver({ obfuscationOptions: hapConfig, compileHar: false, compileShared: false }, printObfLogger);
          const finalConfig = configResolver.resolveObfuscationConfigs();

          expect(finalConfig.options.compact).to.be.false;
          expect(finalConfig.options.removeLog).to.be.false;
          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.enableToplevelObfuscation).to.be.false;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.false;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('RemoteHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteHarMethod');
          expect(finalConfig.reservedGlobalNames).to.include('RemoteHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteHspMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });

        after(() => {
          if (fs.existsSync(remoteHspConfig.exportRulePath)) {
            fs.unlinkSync(remoteHspConfig.exportRulePath);
          }
          if (fs.existsSync(remoteHarConfig.exportRulePath)) {
            fs.unlinkSync(remoteHarConfig.exportRulePath);
          }
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      });

      describe('localHSP depends on localHSP and RemoteHSP Tests', function () {
        before(async () => {
          initModulesConfig();
        });

        it('should contain only MainHSP consumer rules in MainHSP obfuscation.txt', function () {
          localMainHspConfig.dependencies.hspLibraries?.push(localHspConfig.selfConfig);
          localMainHspConfig.dependencies.hsps?.push(remoteHspObfFile);
          const localMainHspResolver = new ObConfigResolver({ obfuscationOptions: localMainHspConfig, compileHar: false, compileShared: true }, printObfLogger);
          localMainHspResolver.resolveObfuscationConfigs();
          localMainHspResolver.emitConsumerConfigFiles();

          const localMainHspObfuscationContent = fs.readFileSync(localMainHspConfig.exportRulePath, 'utf-8');

          expect(localMainHspObfuscationContent).not.to.include('-enable-filename-obfuscation');
          expect(localMainHspObfuscationContent).not.to.include('-remove-log');
          expect(localMainHspObfuscationContent).not.to.include('-enable-property-obfuscation');
          expect(localMainHspObfuscationContent).not.to.include('-enable-toplevel-obfuscation');
          expect(localMainHspObfuscationContent).not.to.include('-enable-string-property-obfuscation');
          expect(localMainHspObfuscationContent).not.to.include('-enable-export-obfuscation');
          expect(localMainHspObfuscationContent).not.to.include('-remove-comments');
          expect(localMainHspObfuscationContent).not.to.include('-compact');
          
          expect(localMainHspObfuscationContent).to.include('-keep-global-name');
          expect(localMainHspObfuscationContent).to.include('-keep-property-name');
          expect(localMainHspObfuscationContent).not.to.include('-keep-file-name');
          expect(localMainHspObfuscationContent).not.to.include('-keep-comments');
          expect(localMainHspObfuscationContent).not.to.include('-keep-dts');

          expect(localMainHspObfuscationContent).to.include('LocalMainHspClass');
          expect(localMainHspObfuscationContent).to.include('localMainHspGreeting');
          expect(localMainHspObfuscationContent).not.to.include('LocalHspClass');
          expect(localMainHspObfuscationContent).not.to.include('localHspMethod');
          expect(localMainHspObfuscationContent).not.to.include('RemoteHspClass');
          expect(localMainHspObfuscationContent).not.to.include('remoteHspMethod');
        });

        it('should only retain MainHSP consumer rules when HAP depends on localMainHsp and localMainHsp depends on localHsp and remoteHsp', function () {
          hapConfig.dependencies.hspLibraries?.push(localMainHspConfig.selfConfig);
          const hapResolver = new ObConfigResolver({ obfuscationOptions: hapConfig, compileHar: false, compileShared: false }, printObfLogger);
          const finalConfig = hapResolver.resolveObfuscationConfigs();

          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.compact).to.be.false;
          expect(finalConfig.options.removeLog).to.be.false;
          expect(finalConfig.options.enableToplevelObfuscation).to.be.false;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.false;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('LocalMainHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('localMainHspGreeting');
          expect(finalConfig.reservedGlobalNames).not.to.include('LocalHspClass');
          expect(finalConfig.reservedPropertyNames).not.to.include('localHspMethod');
          expect(finalConfig.reservedGlobalNames).not.to.include('RemoteHspClass');
          expect(finalConfig.reservedPropertyNames).not.to.include('remoteHspMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });

        after(() => {
          if (fs.existsSync(remoteHspConfig.exportRulePath)) {
            fs.unlinkSync(remoteHspConfig.exportRulePath);
          }
          if (fs.existsSync(localHspConfig.exportRulePath)) {
            fs.unlinkSync(localHspConfig.exportRulePath);
          }
          if (fs.existsSync(localMainHspConfig.exportRulePath)) {
            fs.unlinkSync(localMainHspConfig.exportRulePath);
          }
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      });

      describe('remoteHSP depends on HSP Tests', function () {
        before(async () => {
          initModulesConfig();
        });

        it('should only retain MainHSP consumer rules for HAP when HAP depends on RemoteMainHsp and RemoteMainHsp depends on localHsp and remoteHsp', function () {
          hapConfig.dependencies.hsps?.push(remoteMainHspObfFile);
          const hapResolver = new ObConfigResolver({ obfuscationOptions: hapConfig, compileHar: false, compileShared: false }, printObfLogger);
          const finalConfig = hapResolver.resolveObfuscationConfigs();

          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.compact).to.be.false;
          expect(finalConfig.options.removeLog).to.be.false;
          expect(finalConfig.options.enableToplevelObfuscation).to.be.false;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.false;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('RemoteMainHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteMainHspGreeting');
          expect(finalConfig.reservedGlobalNames).not.to.include('LocalHspClass');
          expect(finalConfig.reservedPropertyNames).not.to.include('localHspMethod');
          expect(finalConfig.reservedGlobalNames).not.to.include('RemoteHspClass');
          expect(finalConfig.reservedPropertyNames).not.to.include('remoteHspMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });

        after(() => {
          if (fs.existsSync(remoteHspConfig.exportRulePath)) {
            fs.unlinkSync(remoteHspConfig.exportRulePath);
          }
          if (fs.existsSync(localHspConfig.exportRulePath)) {
            fs.unlinkSync(localHspConfig.exportRulePath);
          }
          if (fs.existsSync(remoteMainHspConfig.exportRulePath)) {
            fs.unlinkSync(remoteMainHspConfig.exportRulePath);
          }
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      })

      describe('HAP depends on local and remote HAR and HSP Tests', function () {
        before(async () => {
          initModulesConfig();       
        });

        it('should contain all local and remote HAR and HSP consumer rules in final HAP config', function () {
          hapConfig.dependencies.libraries.push(localHarConfig.selfConfig);
          hapConfig.dependencies.hars.push(remoteHarObfFile);
          hapConfig.dependencies.hspLibraries?.push(localHspConfig.selfConfig);
          hapConfig.dependencies.hsps?.push(remoteHspObfFile);
          const hapResolver = new ObConfigResolver({ obfuscationOptions: hapConfig, compileHar: false, compileShared: false }, printObfLogger);
          const finalConfig = hapResolver.resolveObfuscationConfigs();

          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.compact).to.be.false;
          expect(finalConfig.options.removeLog).to.be.false;
          expect(finalConfig.options.enableToplevelObfuscation).to.be.false;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.false;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('LocalHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHarMethod');
          expect(finalConfig.reservedGlobalNames).to.include('LocalHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHspMethod');
          expect(finalConfig.reservedGlobalNames).to.include('RemoteHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteHarMethod');
          expect(finalConfig.reservedGlobalNames).to.include('RemoteHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteHspMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });

        after(() => {
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      });

      describe('-enable-lib-obfuscation-options test', function () {
        before(async () => {
          initModulesConfig();       
        });

        it('should contain all local and remote HAR and HSP consumer rules in final HAP config', function () {
          libTestHapConfig.dependencies.libraries.push(localHarConfig.selfConfig);
          libTestHapConfig.dependencies.hars.push(remoteHarObfFile);
          libTestHapConfig.dependencies.hspLibraries?.push(localHspConfig.selfConfig);
          libTestHapConfig.dependencies.hsps?.push(remoteHspObfFile);
          const hapResolver = new ObConfigResolver(
            { obfuscationOptions: libTestHapConfig, compileHar: false, compileShared: false },
            printObfLogger,
          );
          const finalConfig = hapResolver.resolveObfuscationConfigs();

          expect(finalConfig.options.enableExportObfuscation).to.be.true;
          expect(finalConfig.options.compact).to.be.true;
          expect(finalConfig.options.removeLog).to.be.true;
          expect(finalConfig.options.enableToplevelObfuscation).to.be.true;
          expect(finalConfig.options.enablePropertyObfuscation).to.be.true;
          expect(finalConfig.options.disableObfuscation).to.be.false;
          expect(finalConfig.options.enableFileNameObfuscation).to.be.false;
          expect(finalConfig.options.enableStringPropertyObfuscation).to.be.false;
          expect(finalConfig.options.printKeptNames).to.be.false;
          expect(finalConfig.options.removeComments).to.be.false;

          expect(finalConfig.reservedGlobalNames).to.include('LocalHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHarMethod');
          expect(finalConfig.reservedGlobalNames).to.include('LocalHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('localHspMethod');
          expect(finalConfig.reservedGlobalNames).to.include('RemoteHarClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteHarMethod');
          expect(finalConfig.reservedGlobalNames).to.include('RemoteHspClass');
          expect(finalConfig.reservedPropertyNames).to.include('remoteHspMethod');
          expect(finalConfig.reservedNames.length).to.equal(0);
          expect(finalConfig.reservedFileNames.length).to.equal(0);
          expect(finalConfig.keepComments.length).to.equal(0);
          expect(finalConfig.keepSourceOfPaths.length).to.equal(0);
          expect(finalConfig.universalReservedPropertyNames.length).to.equal(0);
          expect(finalConfig.universalReservedGlobalNames.length).to.equal(0);
          expect(finalConfig.keepUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludeUniversalPaths.length).to.equal(0);
          expect(finalConfig.excludePathSet.size).to.equal(0);
        });

        after(() => {
          if (fs.existsSync(systemApiCacheFile)) {
            fs.unlinkSync(systemApiCacheFile);
          }
        });
      });
    })
  });
})