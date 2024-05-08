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
  ScriptTarget,
  createCompilerHost,
  createProgram,
  createSourceFile,
} from 'typescript';

import type {
  CompilerHost,
  CompilerOptions,
  Program,
  SourceFile,
  TypeChecker,
} from 'typescript';
import { Extension, PathAndExtension } from '../common/type';
import { FileUtils } from './FileUtils';

export class TypeUtils {
  /**
   * Create .d.ets, .d.ts, .ts ast from .d.ets, .d.ts, .ts content.
   * Create .ts ast from .ets, .js content
   * @param {string} sourceFilePath 
   * @param {string} content - The content in sourceFilePath
   */
  public static createObfSourceFile(sourceFilePath: string, content: string): SourceFile {
    const pathOrExtension: PathAndExtension = FileUtils.getFileSuffix(sourceFilePath);
    const fileSuffix = pathOrExtension.ext;

    if (fileSuffix === Extension.JS) {
      sourceFilePath = pathOrExtension.path + Extension.TS;
    }

    return createSourceFile(sourceFilePath, content, ScriptTarget.ES2015, true);
  }

  public static tsToJs(ast: SourceFile): void {
    const pathOrExtension: PathAndExtension = FileUtils.getFileSuffix(ast.fileName);
    const fileSuffix = Extension.JS;
    const targetName: string = pathOrExtension.path + fileSuffix;
    ast.fileName = targetName;
  }

  public static createChecker(ast: SourceFile): TypeChecker {
    const host: CompilerHost = createCompilerHost({});

    const customHost: CompilerHost = {
      getSourceFile(name, languageVersion): SourceFile | undefined {
        if (name === ast.fileName) {
          return ast;
        } else {
          return host.getSourceFile(name, languageVersion);
        }
      },
      // optional
      getDefaultLibLocation: () => '',
      getDefaultLibFileName: () => '',
      writeFile: (filename, data) => {
      },
      getCurrentDirectory: () => '',
      useCaseSensitiveFileNames: host.useCaseSensitiveFileNames,
      getCanonicalFileName: host.getCanonicalFileName,
      getNewLine: host.getNewLine,
      fileExists: () => true,
      readFile: (name): string => {
        return name === ast.fileName ? ast.text : host.readFile(name);
      },
      // must, read program.ts => createCompilerHost
      directoryExists: undefined,
      getEnvironmentVariable: undefined,
      getDirectories: undefined,
    };

    let option: CompilerOptions = {};
    if (ast.fileName.endsWith('.js')) {
      option.allowJs = true;
    }

    let program: Program = createProgram([ast.fileName], option, customHost);
    return program.getTypeChecker();
  }
}
