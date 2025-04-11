/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { KNativePointer as KPtr } from './InteropTypes';
import { global } from './global';
import { throwError } from './utils';
import { passString, passStringArray, unpackString } from './private';
import { isNullPtr } from './Wrapper';

export const arrayOfNullptr = new BigUint64Array([BigInt(0)]);

export abstract class ArktsObject {
  protected constructor(peer: KPtr) {
    this.peer = peer;
  }

  readonly peer: KPtr;
}

export abstract class Node extends ArktsObject {
  protected constructor(peer: KPtr) {
    if (isNullPtr(peer)) {
      throw new Error('trying to create new Node on NULLPTR');
    }
    super(peer);
  }

  public get originalPeer(): KPtr {
    return global.es2panda._AstNodeOriginalNodeConst(global.context, this.peer);
  }

  public set originalPeer(peer: KPtr) {
    global.es2panda._AstNodeSetOriginalNode(global.context, this.peer, peer);
  }

  protected dumpMessage(): string {
    return ``;
  }

  public dumpJson(): string {
    return unpackString(global.es2panda._AstNodeDumpJsonConst(global.context, this.peer));
  }

  public dumpSrc(): string {
    return unpackString(global.es2panda._AstNodeDumpEtsSrcConst(global.context, this.peer));
  }
}

export class Config extends ArktsObject {
  readonly path: string;
  constructor(peer: KPtr, fpath: string) {
    super(peer);
    // TODO: wait for getter from api
    this.path = fpath;
  }

  public toString(): string {
    return `Config (peer = ${this.peer}, path = ${this.path})`;
  }

  static create(input: string[], fpath: string, pandaLibPath: string = '', isEditingMode: boolean = false): Config {
    if (isEditingMode) {
      let cfg = global.es2pandaPublic._CreateConfig(input.length, passStringArray(input), pandaLibPath);
      return new Config(cfg, fpath);
    }
    if (!global.configIsInitialized()) {
      let cfg = global.es2panda._CreateConfig(input.length, passStringArray(input), pandaLibPath);
      global.config = cfg;
      return new Config(cfg, fpath);
    } else {
      return new Config(global.config, fpath);
    }
  }
}

export class Context extends ArktsObject {
  constructor(peer: KPtr) {
    super(peer);
  }

  public toString(): string {
    return `Context (peer = ${this.peer})`;
  }

  static createFromString(source: string): Context {
    if (!global.configIsInitialized()) {
      throwError(`Config not initialized`);
    }
    return new Context(
      global.es2panda._CreateContextFromString(global.config, passString(source), passString(global.filePath))
    );
  }

  static lspCreateFromString(source: string, filePath: string, cfg: Config): KPtr {
    if (cfg === undefined) {
      throwError(`Config not initialized`);
    }
    return global.es2pandaPublic._CreateContextFromString(cfg.peer, passString(source), passString(filePath));
  }
}

// ProjectConfig begins
export interface PluginsConfig {
  [pluginName: string]: string;
}

export interface BuildBaseConfig {
  buildType: 'build' | 'preview' | 'hotreload' | 'coldreload';
  buildMode: 'Debug' | 'Release';
  hasMainModule: boolean;
  arkts: object;
  arktsGlobal: object;
}

export interface ModuleConfig {
  packageName: string;
  moduleType: string;
  moduleRootPath: string;
  sourceRoots: string[];
}

export interface PathConfig {
  loaderOutPath: string;
  declgenDtsOutPath: string;
  declgenTsOutPath: string;
  cachePath: string;
  buildSdkPath: string;
  pandaSdkPath?: string; // path to panda sdk lib/bin, for local test
  pandaStdlibPath?: string; // path to panda sdk stdlib, for local test
  abcLinkerPath?: string;
}

export interface DeclgenConfig {
  enableDeclgenEts2Ts: boolean;
  declgenV1OutPath?: string;
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
}

export interface BuildConfig extends BuildBaseConfig, DeclgenConfig, LoggerConfig, ModuleConfig, PathConfig {
  plugins: PluginsConfig;
  compileFiles: string[];
  dependentModuleList: DependentModuleConfig[];
}
// ProjectConfig ends

export interface CompileFileInfo {
  filePath: string;
  dependentFiles: string[];
  abcFilePath: string;
  arktsConfigFile: string;
  packageName: string;
}

export interface ModuleInfo {
  isMainModule: boolean;
  packageName: string;
  moduleRootPath: string;
  moduleType: string;
  sourceRoots: string[];
  entryFile: string;
  arktsConfigFile: string;
  compileFileInfos: CompileFileInfo[];
  declgenV1OutPath: string | undefined;
  declgenBridgeCodePath: string | undefined;
  dependencies?: string[];
  staticDepModuleInfos: Map<string, ModuleInfo>;
  dynamicDepModuleInfos: Map<string, ModuleInfo>;
  language?: string;
  declFilesPath?: string;
}
