/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

// ProjectConfig begins
export interface PluginsConfig {
  [pluginName: string]: string;
}

export interface PathsConfig {
  [pathName: string]: string[];
}

export interface BuildBaseConfig {
  buildType: 'build' | 'preview' | 'hotreload' | 'coldreload';
  buildMode: 'Debug' | 'Release';
  hasMainModule: boolean;
  arkts: ArkTS;
  arktsGlobal: ArkTSGlobal;
  maxWorkers?: number;
  isBuildConfigModified?: boolean;
}

export interface ArkTSGlobal {
  filePath: string;
  config: object;
  compilerContext: {
    program: object;
    peer: object
  };
  es2panda: {
    _DestroyContext: Function;
    _SetUpSoPath: Function;
  }
}

export interface ArkTS {
  Config: {
    create: Function;
    createContextGenerateAbcForExternalSourceFiles: Function;
  };
  Context: {
    createFromString: Function;
  };
  EtsScript: {
    fromContext: Function;
  };
  proceedToState: Function;
  generateTsDeclarationsFromContext: Function;
  destroyConfig: Function;
  Es2pandaContextState: typeof Es2pandaContextState;
}

export enum Es2pandaContextState {
    ES2PANDA_STATE_NEW = 0,
    ES2PANDA_STATE_PARSED = 1,
    ES2PANDA_STATE_BOUND = 2,
    ES2PANDA_STATE_CHECKED = 3,
    ES2PANDA_STATE_LOWERED = 4,
    ES2PANDA_STATE_ASM_GENERATED = 5,
    ES2PANDA_STATE_BIN_GENERATED = 6,
    ES2PANDA_STATE_ERROR = 7
}

export interface ModuleConfig {
  packageName: string;
  moduleType: string;
  moduleRootPath: string;
  sourceRoots: string[];
  byteCodeHar: boolean;
}

export interface PathConfig {
  loaderOutPath: string;
  cachePath: string;
  buildSdkPath: string;
  pandaSdkPath?: string; // path to panda sdk lib/bin, for local test
  pandaStdlibPath?: string; // path to panda sdk stdlib, for local test
  externalApiPaths: string[];
  abcLinkerPath?: string;
  dependencyAnalyzerPath?: string;
  projectRootPath: string;
}

/**
 * Configuration for framework mode compilation using generate_static_abc gni.
 * 
 * In framework mode, the compiler generates static ABC files from framework SDK ETS files.
 * This mode requires additional arktsconfig.json parameters for proper operation.
 */
export interface FrameworkConfig {
  /**
   * Enables or disables framework compilation mode.
   * When enabled (true), activates special processing rules for framework-level
   * compilation, including different output locations and packaging requirements.
   */
  frameworkMode?: boolean;
  
  /**
   * Determines whether an empty package name should be used.
   * Must be set to true when compiling framework components without a package name.
   */
  useEmptyPackage?: boolean;
}

export interface DeclgenConfig {
  enableDeclgenEts2Ts: boolean;
  declgenV1OutPath?: string;
  declgenV2OutPath?: string;
  declgenBridgeCodePath?: string;
}

export interface LoggerConfig {
  getHvigorConsoleLogger?: Function;
}

export interface DependentModuleConfig {
  packageName: string;
  moduleName: string;
  moduleType: string;
  modulePath: string;
  sourceRoots: string[];
  entryFile: string;
  language: string;
  declFilesPath?: string;
  dependencies?: string[];
  declgenV1OutPath?: string;
  declgenV2OutPath?: string;
  declgenBridgeCodePath?: string;
  byteCodeHar: boolean;
}

export interface BuildConfig extends BuildBaseConfig, DeclgenConfig, LoggerConfig, ModuleConfig, PathConfig, FrameworkConfig {
  plugins: PluginsConfig;
  paths: PathsConfig; // paths config passed from template to generate arktsconfig.json "paths" configs.
  compileFiles: string[];
  dependentModuleList: DependentModuleConfig[];
}
// ProjectConfig ends

export interface CompileFileInfo {
  filePath: string,
  dependentFiles: string[],
  abcFilePath: string,
  arktsConfigFile: string,
  packageName: string,
};

export interface ModuleInfo {
  isMainModule: boolean,
  packageName: string,
  moduleRootPath: string,
  moduleType: string,
  sourceRoots: string[],
  entryFile: string,
  arktsConfigFile: string,
  compileFileInfos: CompileFileInfo[],
  declgenV1OutPath: string | undefined,
  declgenV2OutPath: string | undefined,
  declgenBridgeCodePath: string | undefined,
  dependencies?: string[]
  staticDepModuleInfos: Map<string, ModuleInfo>;
  dynamicDepModuleInfos: Map<string, ModuleInfo>;
  language?: string;
  declFilesPath?: string;
  frameworkMode?: boolean;
  useEmptyPackage?: boolean;
  byteCodeHar: boolean;
}

export type SetupClusterOptions = {
  clearExitListeners?: boolean;
  execPath?: string;
  execArgs?: string[];
};

export interface DependencyFileConfig {
  dependants: {
    [filePath: string]: string[];
  };
  dependencies: {
    [filePath: string]: string[];
  }
}