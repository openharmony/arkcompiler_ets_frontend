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

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as entryModule from '../../../src/entry';
import { BaseMode } from '../../../src/build/base_mode';
import { BuildConfig, BUILD_TYPE, BUILD_MODE, OHOS_MODULE_TYPE, ModuleInfo } from '../../../src/types';
import { BuildMode } from '../../../src/build/build_mode';
import { isWindows, isMac } from '../../../src/utils';
import {
  ErrorCode,
} from '../../../src/error_code';
import cluster, {
  Cluster,
} from 'cluster';

interface Job {
  id: string;
  type?: string;
  dependencies: string[];
  dependants: string[];
  fileList?: string[];
  isDeclFile?: boolean;
  isAbcJob?: boolean;
  isInCycle?: boolean;
  result?: any;
}

interface WorkerInfo {
  worker: ThreadWorker;
  isIdle: boolean;
}

interface ThreadWorker {
  postMessage: (message: any) => void;
}

interface Queues {
  externalProgramQueue: Job[];
  abcQueue: Job[];
}

interface DependencyFileConfig {
  dependencies: Record<string, string[]>;
  dependants: Record<string, string[]>;
}

jest.mock('os', () => ({
  ...jest.requireActual('os'),
  type: jest.fn().mockReturnValue('Darwin')
}));

beforeEach(() => {
  jest.clearAllMocks();
  process.exit = jest.fn() as any;
});

beforeAll(() => {
  const { execSync } = require('child_process');
  execSync('rimraf test/ut/mock/dist', { stdio: 'pipe' });
});

function main(configFilePath?: string): void {
  const buildConfigPath = configFilePath;

  const projectConfig: BuildConfig = JSON.parse(fs.readFileSync(buildConfigPath!, 'utf-8'));

  entryModule.build(projectConfig);
}

describe('test mock isWindows', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(os, 'type').mockReturnValue('Windows_NT');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('test mac001', () => {
    test_mac001();
  });
});

function test_mac001() {
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config4.json";
  main(buildConfigPath);
  expect(isWindows()).toBe(true);
}

describe('test mock isMac', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(os, 'type').mockReturnValue('Darwin');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('test mac002', () => {
    test_mac002();
  });
});

function test_mac002() {
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config5.json";
  main(buildConfigPath);
  expect(isMac()).toBe(true);
}

describe('test base_mode.ts file api', () => {
  test('test collectModuleInfos', () => {
    test_collectModuleInfos();
  });

  test('test collectDependentCompileFiles002', () => {
    test_collectDependentCompileFiles002();
  });

  test('test shouldSkipFile', () => {
    test_shouldSkipFile();
  });

  test('test setupCluster', () => {
    test_setupCluster();
  });

  test('test terminateAllWorkers', () => {
    test_terminateAllWorkers();
  });

  test('test collectModuleInfos 001', () => {
    test_collectDependencyModules001();
  });

  test('test collectModuleInfos 002', () => {
    test_collectDependencyModules002();
  });

  test('test runall new', () => {
    test_runParallell1();
  });

  test('test test_collectAbcFileFromByteCodeHar', () => {
    test_collectAbcFileFromByteCodeHar();
  });

  test('test getDependentModules', async () => {
    test_getDependentModules();
  });

  test('collectCompileFiles: test declaration files skip branch', () => {
    test_collectCompileFiles_decl_ets_skip();
  });

  test('collectCompileFiles: test bytecode HAR branch', () => {
    test_collectCompileFiles_bytecode_har();
  });

  test('collectCompileFiles: test file not in module path branch', () => {
    test_collectCompileFiles_file_not_in_module();
  });

  test('test createExternalProgramJob method branches', () => {
    test_createExternalProgramJob_branches();
  });

  test('test findStronglyConnectedComponents method branches', () => {
    test_findStronglyConnectedComponents_branches();
  });

  test('test assignTaskToIdleWorker abcQueue branch without job', () => {
    test_assignTaskToIdleWorker_abcQueue_no_job();
  });

  test('test assignTaskToIdleWorker with empty queues', () => {
    test_assignTaskToIdleWorker_empty_queues();
  });
});

function test_assignTaskToIdleWorker_empty_queues() {
  const mockLogger = {
    printInfo: jest.fn(),
    printError: jest.fn()
  };

  const mockConfig = {
    packageName: "test",
    moduleType: "har",
    buildMode: BUILD_MODE.DEBUG,
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache"
  };

  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance = jest.fn().mockReturnValue(mockLogger);

  class TestBaseMode extends BaseMode {
    public run(): Promise<void> {
      return Promise.resolve();
    }

    public testAssignTaskToIdleWorker(
      workerInfo: WorkerInfo,
      queues: Queues,
      processingJobs: Set<string>,
      serializableConfig: Object,
      globalContextPtr: any
    ): void {
      (this as any).assignTaskToIdleWorker(
        workerInfo,
        queues,
        processingJobs,
        serializableConfig,
        globalContextPtr
      );
    }
  }
  const baseMode = new TestBaseMode(mockConfig as any);
  const mockWorker = {
    postMessage: jest.fn()
  };

  const workerInfo: WorkerInfo = {
    worker: mockWorker as unknown as ThreadWorker,
    isIdle: true
  };

  const queues: Queues = {
    externalProgramQueue: [],
    abcQueue: []
  };

  const processingJobs = new Set<string>();
  const serializableConfig = {};
  const globalContextPtr = {};

  (baseMode as any).allFiles = new Map([
    ['test/file.ets', {
      filePath: 'test/file.ets',
      packageName: 'test',
      arktsConfigFile: 'test/config.json',
      abcFilePath: './dist/file.abc'
    }]
  ]);

  const postMessageSpy = jest.spyOn(mockWorker, 'postMessage');

  baseMode.testAssignTaskToIdleWorker(
    workerInfo,
    queues,
    processingJobs,
    serializableConfig,
    globalContextPtr
  );

  expect(postMessageSpy).not.toHaveBeenCalled();
  expect(processingJobs.size).toBe(0);
  expect(workerInfo.isIdle).toBe(true);
  jest.restoreAllMocks();
}

function test_assignTaskToIdleWorker_abcQueue_no_job() {
  const mockLogger = {
    printInfo: jest.fn(),
    printError: jest.fn()
  };

  const mockConfig = {
    packageName: "test",
    moduleType: "har",
    buildMode: BUILD_MODE.DEBUG,
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache"
  };

  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance = jest.fn().mockReturnValue(mockLogger);

  class TestBaseMode extends BaseMode {
    public run(): Promise<void> {
      return Promise.resolve();
    }
    public testAssignTaskToIdleWorker(
      workerInfo: WorkerInfo,
      queues: Queues,
      processingJobs: Set<string>,
      serializableConfig: Object,
      globalContextPtr: any
    ): void {
      (this as any).assignTaskToIdleWorker(
        workerInfo,
        queues,
        processingJobs,
        serializableConfig,
        globalContextPtr
      );
    }
  }

  const baseMode = new TestBaseMode(mockConfig as any);

  const mockWorker = {
    postMessage: jest.fn()
  };

  const workerInfo: WorkerInfo = {
    worker: mockWorker as unknown as ThreadWorker,
    isIdle: true
  };

  const queues: Queues = {
    externalProgramQueue: [],
    abcQueue: [{
      id: 'abc:test/nonexistentfile.ets',
      type: 'abc',
      dependencies: [],
      dependants: [],
      result: null,
      fileList: ['test/nonexistentfile.ets'],
      isDeclFile: false,
      isAbcJob: true
    }]
  };

  const processingJobs = new Set<string>();
  const serializableConfig = {};
  const globalContextPtr = {};

  (baseMode as any).allFiles = new Map([
    ['test/otherfile.ets', {
      filePath: 'test/otherfile.ets',
      packageName: 'test',
      arktsConfigFile: 'test/config.json',
      abcFilePath: './dist/otherfile.abc'
    }]
  ]);

  const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
  const postMessageSpy = jest.spyOn(mockWorker, 'postMessage');
  try {
    baseMode.testAssignTaskToIdleWorker(
      workerInfo,
      queues,
      processingJobs,
      serializableConfig,
      globalContextPtr
    );
    fail('Expected method to throw, but it did not');
  } catch (error) {
    expect(error).toBeInstanceOf(ReferenceError);
    expect(workerInfo.isIdle).toBe(false);
  } finally {
    consoleSpy.mockRestore();
    jest.restoreAllMocks();
  }
}

function test_findStronglyConnectedComponents_branches() {
  const mockConfig = {
    packageName: "test", moduleRootPath: "/test/path", sourceRoots: ["./"],
    loaderOutPath: "./dist", cachePath: "./dist/cache", buildMode: "Debug"
  };

  class TestBaseMode extends BaseMode {
    public run(): Promise<void> { return Promise.resolve(); }
    public testFindStronglyConnectedComponents(graph: DependencyFileConfig): Map<string, Set<string>> {
      return (this as any).findStronglyConnectedComponents(graph);
    }
    protected createHash(input: string): string { return 'cycle-group-' + input.length; }
  }

  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance = jest.fn().mockReturnValue({ printInfo: jest.fn(), printError: jest.fn() });
  const baseMode = new TestBaseMode(mockConfig as any);
  const graph1 = {
    dependencies: { 'A': ['B', 'C'], 'B': ['C'], 'C': ['A'] },
    dependants: { 'A': ['C'], 'B': ['A'], 'C': ['A', 'B'] }
  };
  const result1 = baseMode.testFindStronglyConnectedComponents(graph1);
  expect(result1.size).toBe(1);
  expect(Array.from(result1.values())[0].size).toBe(3);
  const graph2 = {
    dependencies: { 'A': ['B', 'C'], 'B': ['D'], 'C': ['D'], 'D': ['E'], 'E': ['B'] },
    dependants: { 'A': [], 'B': ['A', 'E'], 'C': ['A'], 'D': ['B', 'C'], 'E': ['D'] }
  };
  const result2 = baseMode.testFindStronglyConnectedComponents(graph2);
  expect(result2.size).toBe(1);
  expect(Array.from(result2.values())[0].size).toBe(3);
  const graph3 = {
    dependencies: { 'A': ['B'], 'B': ['C'], 'C': ['D'], 'D': [], 'E': ['F'], 'F': ['E'] },
    dependants: { 'A': [], 'B': ['A'], 'C': ['B'], 'D': ['C'], 'E': ['F'], 'F': ['E'] }
  };
  const result3 = baseMode.testFindStronglyConnectedComponents(graph3);
  expect(result3.size).toBe(1);
  expect(Array.from(result3.values())[0].size).toBe(2);
  const graph4 = {
    dependencies: { 'A': ['B'], 'B': ['C'], 'C': ['D'], 'D': [] },
    dependants: { 'A': [], 'B': ['A'], 'C': ['B'], 'D': ['C'] }
  };
  const result4 = baseMode.testFindStronglyConnectedComponents(graph4);
  expect(result4.size).toBe(0);
}

function test_createExternalProgramJob_branches() {
  const mockConfig = {
    packageName: "test",
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    buildMode: "Debug",
    moduleType: "har"
  };

  class TestBaseMode extends BaseMode {
    public run(): Promise<void> {
      return Promise.resolve();
    }

    public testCreateExternalProgramJob(id: string, fileList: string[], jobs: Record<string, Job>, dependencies: Set<string>, isInCycle?: boolean): void {
      return (this as any).createExternalProgramJob(id, fileList, jobs, dependencies, isInCycle);
    }
  }

  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance = jest.fn().mockReturnValue({
    printInfo: jest.fn(),
    printError: jest.fn()
  });

  const baseMode = new TestBaseMode(mockConfig as any);

  {
    const id = "external-program:test/file.ets";
    const fileList = ["test/file.ets"];
    const jobs: Record<string, Job> = {};
    const dependencies = new Set<string>([id, "external-program:other.ets"]);
    const isInCycle = false;

    baseMode.testCreateExternalProgramJob(id, fileList, jobs, dependencies, isInCycle);

    expect(dependencies.has(id)).toBe(false);
    expect(dependencies.size).toBe(1);

    expect(jobs[id]).toBeDefined();
    expect(jobs[id].id).toBe(id);
    expect(jobs[id].fileList).toEqual(fileList);
    expect(jobs[id].isDeclFile).toBe(true);
    expect(jobs[id].isInCycle).toBe(false);
    expect(jobs[id].dependencies).toEqual(["external-program:other.ets"]);
    expect(jobs[id].dependants).toEqual([]);
  }

  {
    const id = "external-program:test/file2.ets";
    const fileList = ["test/file2.ets", "test/file2b.ets"];
    const jobs: Record<string, Job> = {
      [id]: {
        id,
        fileList: ["test/file2.ets"],
        isDeclFile: false,
        isInCycle: false,
        isAbcJob: false,
        dependencies: ["external-program:dep1.ets"],
        dependants: ["external-program:dep3.ets"]
      }
    };

    const dependencies = new Set<string>(["external-program:dep2.ets"]);
    const isInCycle = true;

    baseMode.testCreateExternalProgramJob(id, fileList, jobs, dependencies, isInCycle);

    expect(jobs[id]).toBeDefined();
    expect(jobs[id].id).toBe(id);
    expect(jobs[id].fileList).toEqual(["test/file2.ets"]);
    expect(jobs[id].isDeclFile).toBe(false);
    expect(jobs[id].isInCycle).toBe(false);
    expect(jobs[id].dependencies).toContain("external-program:dep1.ets");
    expect(jobs[id].dependencies).toContain("external-program:dep2.ets");
    expect(jobs[id].dependencies.length).toBe(2);
    expect(jobs[id].dependants).toEqual(["external-program:dep3.ets"]);
  }
}

function test_collectCompileFiles_bytecode_har() {
  const mockLogger = {
    printInfo: jest.fn(),
    printError: jest.fn()
  };

  const mockConfig = {
    packageName: "test",
    moduleType: "har",
    buildMode: BUILD_MODE.DEBUG,
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    enableDeclgenEts2Ts: true,
    dependentModuleList: []
  };

  class TestBaseMode extends BaseMode {
    public run(): Promise<void> {
      return Promise.resolve();
    }

    public testCollectCompileFiles(): void {
      this.collectCompileFiles();
    }

    public testCollectAbcFileFromByteCodeHar(): void {
      this.collectAbcFileFromByteCodeHar();
    }
  }

  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance = jest.fn().mockReturnValue(mockLogger);
  const baseMode = new TestBaseMode(mockConfig as any);

  (baseMode as any).cacheDir = "./dist/cache";
  (baseMode as any).abcFiles = new Set();
  (baseMode as any).hashCache = {};
  (baseMode as any).compileFiles = new Map();

  (baseMode as any).entryFiles = new Set([
    '/test/path/test.ets'
  ]);

  (baseMode as any).moduleInfos = new Map();
  (baseMode as any).moduleInfos.set("test", {
    packageName: "test",
    moduleType: "har",
    byteCodeHar: true,
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    arktsConfigFile: "./dist/cache/test/config.json",
    compileFileInfos: []
  });

  (global as any).getFileHash = jest.fn().mockReturnValue("hash123");
  const utils = require('../../../src/utils');

  jest.spyOn(baseMode, 'testCollectAbcFileFromByteCodeHar').mockImplementation(() => { });

  baseMode.testCollectCompileFiles();
}

function test_collectCompileFiles_file_not_in_module() {
  const mockLogger = {
    printInfo: jest.fn(),
    printError: jest.fn()
  };

  const mockConfig = {
    packageName: "test",
    moduleType: "har",
    buildMode: BUILD_MODE.DEBUG,
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    enableDeclgenEts2Ts: true,
    dependentModuleList: []
  };

  class TestBaseMode extends BaseMode {
    public run(): Promise<void> {
      return Promise.resolve();
    }

    public testCollectCompileFiles(): void {
      this.collectCompileFiles();
    }
  }

  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance = jest.fn().mockReturnValue(mockLogger);
  const baseMode = new TestBaseMode(mockConfig as any);

  (baseMode as any).cacheDir = "./dist/cache";
  (baseMode as any).abcFiles = new Set();
  (baseMode as any).hashCache = {};
  (baseMode as any).compileFiles = new Map();

  (baseMode as any).entryFiles = new Set([
    '/other/path/test.ets'
  ]);

  (baseMode as any).moduleInfos = new Map();
  (baseMode as any).moduleInfos.set("test", {
    packageName: "test",
    moduleType: "har",
    byteCodeHar: false,
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    arktsConfigFile: "./dist/cache/test/config.json",
    compileFileInfos: []
  });

  baseMode.testCollectCompileFiles();

  expect(mockLogger.printError).toHaveBeenCalledWith(
    expect.objectContaining({
      code: ErrorCode.BUILDSYSTEM_FILE_NOT_BELONG_TO_ANY_MODULE_FAIL,
      description: 'File does not belong to any module in moduleInfos.'
    })
  );

  expect((baseMode as any).compileFiles.size).toBe(0);
}

function test_collectCompileFiles_decl_ets_skip() {
  const mockLogger = {
    printInfo: jest.fn(),
    printError: jest.fn()
  };

  const mockConfig = {
    packageName: "test",
    moduleType: "har",
    buildMode: BUILD_MODE.DEBUG,
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    enableDeclgenEts2Ts: true,
    dependentModuleList: []
  };

  class TestBaseMode extends BaseMode {
    public run(): Promise<void> {
      return Promise.resolve();
    }

    public testCollectCompileFiles(): void {
      this.collectCompileFiles();
    }
  }

  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance = jest.fn().mockReturnValue(mockLogger);
  const baseMode = new TestBaseMode(mockConfig as any);

  (baseMode as any).cacheDir = "./dist/cache";
  (baseMode as any).abcFiles = new Set();
  (baseMode as any).hashCache = {};
  (baseMode as any).compileFiles = new Map();

  (baseMode as any).entryFiles = new Set([
    './test/ut/mock/demo_1.2_dep_hsp1.2/hspA/index.ets',
    '/test/path/test.d.ets'
  ]);

  (baseMode as any).moduleInfos = new Map();
  (baseMode as any).moduleInfos.set("test", {
    packageName: "test",
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    arktsConfigFile: "./dist/cache/test/config.json",
    compileFileInfos: []
  });

  (global as any).getFileHash = jest.fn().mockReturnValue("hash123");
  const utils = require('../../../src/utils');

  baseMode.testCollectCompileFiles();
}

function test_collectDependencyModules001() {
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config6.json";
  main(buildConfigPath);
}

function test_collectDependencyModules002() {
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config7.json";
  main(buildConfigPath);
}

function test_collectAbcFileFromByteCodeHar() {
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config8.json";
  main(buildConfigPath);
}

function test_getDependentModules() {
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config9.json";
  main(buildConfigPath);
}

async function test_runParallell1() {
  const mockLogger = {
    printInfo: jest.fn(),
    printError: jest.fn()
  };

  const mockCluster = {
    isPrimary: true,
    fork: jest.fn().mockReturnValue({
      on: jest.fn(),
      send: jest.fn()
    }),
    workers: {},
    removeAllListeners: jest.fn(),
    setupPrimary: jest.fn()
  };

  jest.spyOn(cluster, 'fork').mockImplementation(mockCluster.fork);
  jest.spyOn(cluster, 'removeAllListeners').mockImplementation(mockCluster.removeAllListeners);
  jest.spyOn(cluster, 'setupPrimary').mockImplementation(mockCluster.setupPrimary);

  const mockConfig = {
    packageName: "test",
    compileFiles: ["test/file.ets"],
    moduleRootPath: "test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    buildMode: "Debug"
  };

  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance(mockConfig);

  class TestBuildMode extends BuildMode {

    public generateModuleInfos(): void {
    }

    public setupCluster(): void {
    }

    public mergeAbcFiles(): void {
    }
  }

  const baseMode = new TestBuildMode(mockConfig as any);

  jest.spyOn(baseMode, 'generateModuleInfos').mockImplementation(() => { });
  jest.spyOn(baseMode, 'setupCluster').mockImplementation(() => { });
  jest.spyOn(baseMode, 'mergeAbcFiles').mockImplementation(() => { });

  (baseMode as any).logger = mockLogger;

  await baseMode.runParallell();

  expect(baseMode.generateModuleInfos).toHaveBeenCalled();
  expect(baseMode.setupCluster).toHaveBeenCalled();
  expect(baseMode.mergeAbcFiles).toHaveBeenCalled();
}

function test_collectModuleInfos() {
  const mockLogger = {
    printError: jest.fn(),
    printInfo: jest.fn()
  };
  const mockConfig: BuildConfig = {
    buildMode: BUILD_MODE.DEBUG,
    compileFiles: ["test.ets"],
    packageName: "test",
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    plugins: {},
    buildType: BUILD_TYPE.BUILD,
    hasMainModule: true,
    moduleType: OHOS_MODULE_TYPE.HAR,
    arkts: {} as any,
    arktsGlobal: {} as any,
    enableDeclgenEts2Ts: false,
    byteCodeHar: false,
    declgenV1OutPath: "./dist/declgen",
    declgenV2OutPath: "./dist/declgen/v2",
    buildSdkPath: "./sdk",
    externalApiPaths: [],

    dependentModuleList: [
      {
        "packageName": "",
        "moduleName": "harA",
        "moduleType": "har",
        "modulePath": "test/ut/mock/demo_1.2_dep_hsp1.2/harA",
        "sourceRoots": ["./"],
        "entryFile": "index.ets",
        "language": "11.2",
        "dependencies": ["hspA"],
        "byteCodeHar": false
      },
      {
        "packageName": "",
        "moduleName": "hspA",
        "moduleType": "shared",
        "modulePath": "test/ut/mock/demo_1.2_dep_hsp1.2/hspA",
        "sourceRoots": ["./"],
        "entryFile": "test/ut/mock/demo_1.2_dep_hsp1.2/hspA/index.ets",
        "language": "11.2",
        "byteCodeHar": false
      }
    ]
  };
  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance(mockConfig);
  let baseModule: BuildMode = new BuildMode(mockConfig);
  (baseModule as any).collectModuleInfos();

  expect(mockLogger.printError).not.toHaveBeenCalledWith(
    expect.objectContaining({
      code: ErrorCode.BUILDSYSTEM_MODULE_INFO_NOT_CORRECT_FAIL,
      description: 'Main module info from hvigor is not correct.'
    })
  );
}

function test_collectDependentCompileFiles002() {
  const mockLogger = {
    printError: jest.fn(),
    printInfo: jest.fn(),
    hasErrors: jest.fn().mockReturnValue(false)
  };

  const moduleRootPath = "test/ut/mock/demo_1.2_dep_hsp1.2/entry/";
  const testFile = `${moduleRootPath}a.ets`;

  const mockConfig: BuildConfig = {
    compileFiles: [testFile],
    packageName: "entry",
    moduleType: OHOS_MODULE_TYPE.HAR,
    buildType: BUILD_TYPE.BUILD,
    buildMode: BUILD_MODE.DEBUG,
    moduleRootPath: moduleRootPath,
    sourceRoots: ["./"],
    loaderOutPath: "test/ut/mock/dist",
    cachePath: "test/ut/mock/dist/cache",
    dependentModuleList: [],
    plugins: {},
    hasMainModule: false,
    arkts: {} as any,
    arktsGlobal: {} as any,
    enableDeclgenEts2Ts: false,
    byteCodeHar: false,
    declgenV1OutPath: "./dist/declgen",
    declgenV2OutPath: "./dist/declgen/v2",
    buildSdkPath: "./sdk",
    externalApiPaths: []
  };

  const BaseMode = require('../../../src/build/base_mode').BaseMode;
  const BuildMode = require('../../../src/build/build_mode').BuildMode;
  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance(mockConfig);
  let baseModule = new BuildMode(mockConfig);

  (baseModule as any).logger = mockLogger;
  (baseModule as any).moduleInfos = new Map();
  (baseModule as any).moduleInfos.set("entry", {
    packageName: "entry",
    moduleRootPath: moduleRootPath,
    sourceRoots: ["./"],
    compileFileInfos: []
  });

  (baseModule as any).entryFiles = new Set([testFile]);
  (baseModule as any).dependencyFileMap = {
    dependants: {
      [testFile]: ["dependency1.ets", "dependency2.ets"]
    }
  };
  (baseModule as any).cacheDir = "test/ut/mock/dist/cache";
  (baseModule as any).hashCache = {};
  (baseModule as any).abcFiles = new Set();
  (baseModule as any).compileFiles = new Map();

  (baseModule as any).isBuildConfigModified = true;

  (baseModule as any).isFileChanged = jest.fn().mockReturnValue(false);

  (baseModule as any).collectDependentCompileFiles();

  expect(mockLogger.printError).not.toHaveBeenCalledWith(
    expect.objectContaining({
      code: ErrorCode.BUILDSYSTEM_FILE_NOT_BELONG_TO_ANY_MODULE_FAIL,
      message: 'File does not belong to any module in moduleInfos.'
    })
  );

  expect((baseModule as any).abcFiles.size).toBe(1);
  const compileFilesArray = Array.from((baseModule as any).compileFiles.keys());
  expect(compileFilesArray.length).toBe(1);
  expect(compileFilesArray[0]).toBe(testFile);
}

function test_shouldSkipFile() {
  const mockLogger = { printError: jest.fn() };
  const mockConfig: BuildConfig = {
    buildMode: BUILD_MODE.DEBUG,
    compileFiles: ["test.ets"],
    packageName: "test",
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    plugins: {},
    dependentModuleList: [],
    buildType: BUILD_TYPE.BUILD,
    hasMainModule: false,
    moduleType: OHOS_MODULE_TYPE.HAR,
    byteCodeHar: false,
    arkts: {} as any,
    arktsGlobal: {} as any,
    declgenV1OutPath: "./dist/declgen",
    declgenV2OutPath: "./dist/declgen/v2",
    buildSdkPath: "./sdk",
    externalApiPaths: [],
    enableDeclgenEts2Ts: false
  };
  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance(mockConfig);
  let baseModule: BaseMode = new BuildMode(mockConfig);
  (baseModule as any).logger = mockLogger;
  (baseModule as any).hashCache = {
    "/test/path/file.ets": "hash123"
  };

  const file = "/test/path/file.ets";
  const moduleInfo: ModuleInfo = {
    isMainModule: false,
    packageName: "test",
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    arktsConfigFile: "/cache/test/arktsconfig.json",
    compileFileInfos: [],
    declgenV1OutPath: "/dist/declgen",
    declgenBridgeCodePath: "/dist/bridge",
    dynamicDepModuleInfos: new Map(),
    staticDepModuleInfos: new Map(),
    moduleType: OHOS_MODULE_TYPE.HAR,
    entryFile: "index.ets",
    declgenV2OutPath: "/dist/declgen/v2",
    byteCodeHar: false
  };
  const filePathFromModuleRoot = "file.ets";
  const abcFilePath = "/cache/test/file.abc";

  (baseModule as any).enableDeclgenEts2Ts = true;
  let result3 = (baseModule as any).shouldSkipFile(file, moduleInfo, filePathFromModuleRoot, abcFilePath);
  (baseModule as any).enableDeclgenEts2Ts = false;
  let result4 = (baseModule as any).shouldSkipFile(file, moduleInfo, filePathFromModuleRoot, abcFilePath);
  expect(result3).toBe(false);
  expect(result4).toBe(false);
}

function test_setupCluster() {
  const mockConfig: BuildConfig = {
    buildMode: BUILD_MODE.DEBUG,
    compileFiles: ["test.ets"],
    packageName: "test",
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    plugins: {},
    dependentModuleList: [],
    maxWorkers: 1,
    buildType: BUILD_TYPE.BUILD,
    hasMainModule: true,
    arkts: {} as any,
    arktsGlobal: {} as any,
    enableDeclgenEts2Ts: false,
    moduleType: OHOS_MODULE_TYPE.HAR,
    declgenV1OutPath: "./dist/declgen",
    declgenV2OutPath: "./dist/declgen/v2",
    buildSdkPath: "./sdk",
    byteCodeHar: false,
    externalApiPaths: []
  };
  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance(mockConfig);
  let baseModule: BaseMode = new BuildMode(mockConfig);

  const originalRemoveAllListeners = cluster.removeAllListeners;
  const originalSetupPrimary = cluster.setupPrimary;

  const removeAllListenersSpy = jest.fn();
  cluster.removeAllListeners = removeAllListenersSpy;

  const setupPrimarySpy = jest.fn();
  cluster.setupPrimary = setupPrimarySpy;

  try {
    (baseModule as any).setupCluster(cluster, {
      clearExitListeners: false,
      execPath: '/path/to/worker',
      execArgs: []
    });

    expect(removeAllListenersSpy).not.toHaveBeenCalled();
    expect(setupPrimarySpy).toHaveBeenCalledWith({
      exec: '/path/to/worker',
      execArgv: []
    });
  } finally {
    cluster.removeAllListeners = originalRemoveAllListeners;
    cluster.setupPrimary = originalSetupPrimary;
  }
}

function test_terminateAllWorkers() {
  const mockConfig: BuildConfig = {
    buildMode: BUILD_MODE.DEBUG,
    compileFiles: ["test.ets"],
    packageName: "test",
    moduleRootPath: "/test/path",
    sourceRoots: ["./"],
    loaderOutPath: "./dist",
    cachePath: "./dist/cache",
    plugins: {},
    dependentModuleList: [],
    buildType: BUILD_TYPE.BUILD,
    hasMainModule: true,
    arkts: {} as any,
    arktsGlobal: {} as any,
    enableDeclgenEts2Ts: false,
    moduleType: OHOS_MODULE_TYPE.HAR,
    declgenV1OutPath: "./dist/declgen",
    declgenV2OutPath: "./dist/declgen/v2",
    buildSdkPath: "./sdk",
    byteCodeHar: false,
    externalApiPaths: []
  };
  const Logger = require('../../../src/logger').Logger;
  Logger.instance = null;
  Logger.getInstance(mockConfig);
  let baseModule: BaseMode = new BuildMode(mockConfig);

  const originalWorkers = cluster.workers;

  try {
    Object.defineProperty(cluster, 'workers', {
      value: {},
      configurable: true
    });

    expect(() => {
      (baseModule as any).terminateAllWorkers();
    }).not.toThrow();

    Object.defineProperty(cluster, 'workers', {
      value: undefined,
      configurable: true
    });

    expect(() => {
      (baseModule as any).terminateAllWorkers();
    }).not.toThrow();
  } finally {
    Object.defineProperty(cluster, 'workers', {
      value: originalWorkers,
      configurable: true
    });
  }
}
