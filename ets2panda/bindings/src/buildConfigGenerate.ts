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
import * as path from 'path';
import * as JSON5 from 'json5';
import { BuildConfig } from './types';

export interface ModuleDescriptor {
  arktsversion: string;
  name: string;
  moduleType: string;
  srcPath: string;
}

interface Json5Object {
  module?: {
    type?: string;
  };
  modules?: Array<{
    name: string;
    srcPath: string;
    arktsversion?: string;
  }>;
  dependencies?: {
    [packageName: string]: string;
  };
}

function removeTrailingCommas(jsonString: string): string {
  return jsonString.replace(/,\s*([}\]])/g, '$1');
}

function parseJson5(filePath: string): Json5Object {
  try {
    const rawContent = fs.readFileSync(filePath, 'utf8');
    const cleanedContent = removeTrailingCommas(rawContent);
    return JSON5.parse(cleanedContent) as Json5Object;
  } catch (error) {
    console.error(`Error parsing ${filePath}:`, error);
    return {} as Json5Object;
  }
}

function getModuleTypeFromConfig(modulePath: string): string {
  const moduleConfigPath = path.join(modulePath, 'src/main/module.json5');
  if (fs.existsSync(moduleConfigPath)) {
    try {
      const moduleData = parseJson5(moduleConfigPath);
      return moduleData.module?.type || 'har';
    } catch (error) {
      console.error(`Error parsing ${moduleConfigPath}:`, error);
    }
  }
  return 'har';
}

function getModulesFromBuildProfile(buildProfilePath: string): ModuleDescriptor[] {
  if (!fs.existsSync(buildProfilePath)) {
    console.error('Error: build-profile.json5 not found');
    process.exit(1);
  }

  const buildProfile = parseJson5(buildProfilePath);
  const modules = buildProfile.modules || [];

  return modules.map((module: { name: string; srcPath: string; arktsversion?: string }) => {
    const moduleSrcPath = path.resolve(path.dirname(buildProfilePath), module.srcPath);
    const arktsversion = module.arktsversion || '1.1';
    return {
      name: module.name,
      moduleType: getModuleTypeFromConfig(moduleSrcPath),
      srcPath: moduleSrcPath,
      arktsversion
    };
  });
}

function getEtsFiles(modulePath: string): string[] {
  const files: string[] = [];

  const shouldSkipDirectory = (relativePath: string): boolean => {
    const testDir1 = `src${path.sep}test`;
    const testDir2 = `src${path.sep}ohosTest`;
    return relativePath.startsWith(testDir1) || relativePath.startsWith(testDir2);
  };

  const processEntry = (dir: string, entry: fs.Dirent): void => {
    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(modulePath, fullPath);

    if (entry.isDirectory()) {
      if (shouldSkipDirectory(relativePath)) {
        return;
      }
      traverseDir(fullPath);
      return;
    }

    if (entry.isFile() && entry.name.endsWith('.ets')) {
      files.push(fullPath);
    }
  };

  const traverseDir = (dir: string): void => {
    if (!fs.existsSync(dir)) {
      return;
    }

    const entries = fs.readdirSync(dir, { withFileTypes: true });
    entries.forEach((entry) => processEntry(dir, entry));
  };

  traverseDir(modulePath);
  return files;
}

function getModuleDependencies(modulePath: string, visited = new Set<string>()): string[] {
  if (visited.has(modulePath)) {
    return [];
  }
  visited.add(modulePath);

  const extractDependencies = (): string[] => {
    const packageFilePath = path.join(modulePath, 'oh-package.json5');
    if (!fs.existsSync(packageFilePath)) {
      return [];
    }

    try {
      const packageData = parseJson5(packageFilePath);
      return Object.entries(packageData.dependencies || {})
        .map(([_, depPath]) => (depPath as string).replace('file:', ''))
        .map((depPath) => path.resolve(modulePath, depPath));
    } catch (error) {
      console.error(`Error parsing ${packageFilePath}:`, error);
      return [];
    }
  };

  const resolveNestedDependencies = (deps: string[]): string[] => {
    return deps.flatMap((depPath) =>
      visited.has(depPath) ? [] : [depPath, ...getModuleDependencies(depPath, visited)]
    );
  };

  const dependencies = extractDependencies();
  const nestedDependencies = resolveNestedDependencies(dependencies);
  return Array.from(new Set([...dependencies, ...nestedDependencies]));
}

export function generateBuildConfigs(
  buildSdkPath: string,
  projectRoot: string,
  modules?: ModuleDescriptor[]
): Record<string, BuildConfig> {
  const allBuildConfigs: Record<string, BuildConfig> = {};

  if (!modules) {
    const buildProfilePath = path.join(projectRoot, 'build-profile.json5');
    modules = getModulesFromBuildProfile(buildProfilePath);
  }

  const definedModules = modules;
  const cacheDir = path.join(projectRoot, '.idea', '.deveco');

  for (const module of definedModules) {
    const modulePath = module.srcPath;
    const compileFiles = new Set(getEtsFiles(modulePath));

    // Get recursive dependencies
    const dependencies = getModuleDependencies(modulePath);
    for (const depPath of dependencies) {
      getEtsFiles(depPath).forEach((file) => compileFiles.add(file));
    }

    allBuildConfigs[module.name] = {
      plugins: {
        'ui-plugins': path.join(buildSdkPath, 'build-tools', 'ui-plugins', 'lib', 'ui-plugins', 'index'),
        'memo-plugin': path.join(buildSdkPath, 'build-tools', 'ui-plugins', 'lib', 'memo-plugins', 'index')
      },
      arkts: {},
      arktsGlobal: {},
      compileFiles: Array.from(compileFiles),
      packageName: module.name,
      moduleType: module.moduleType,
      buildType: 'build',
      buildMode: 'Debug',
      moduleRootPath: modulePath,
      sourceRoots: ['./'],
      hasMainModule: true,
      loaderOutPath: path.join(modulePath, 'build', 'default', 'cache'),
      cachePath: cacheDir,
      buildSdkPath: buildSdkPath,
      enableDeclgenEts2Ts: false,
      declgenDtsOutPath: path.join(modulePath, 'build', 'default', 'cache'),
      declgenTsOutPath: path.join(modulePath, 'build', 'default', 'cache'),
      dependentModuleList: dependencies.map((dep) => {
        const depModule = definedModules.find((m) => m.srcPath === dep);
        return {
          packageName: path.basename(dep),
          moduleName: path.basename(dep),
          moduleType: depModule ? depModule.moduleType : 'har',
          modulePath: dep,
          sourceRoots: ['./'],
          entryFile: 'index.ets',
          language: depModule ? depModule.arktsversion : '1.1'
        };
      })
    };
  }
  const outputPath = path.join(cacheDir, 'lsp_build_config.json');
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }
  fs.writeFileSync(outputPath, JSON.stringify(allBuildConfigs, null, 4));
  return allBuildConfigs;
}
