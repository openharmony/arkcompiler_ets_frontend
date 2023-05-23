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
  createCompilerHost,
  createPrinter,
  createProgram,
  createSourceFile,
  ScriptTarget,
} from 'typescript';

import type {
  CompilerHost,
  CompilerOptions,
  Printer,
  Program,
  SourceFile,
  TypeChecker,
} from 'typescript';

import path from 'path';

export class TypeUtils {
  /**
   * performing symbol analysis on the original abstract syntax tree can cause sourcemap errors
   * @param oldAst
   *
   */
  public static createNewSourceFile(oldAst: SourceFile): SourceFile {
    let printer: Printer = createPrinter();
    let content: string = printer.printFile(oldAst);

    const fileSuffix: string = '.ts';
    const { dir, name } = path.parse(oldAst.fileName);
    const targetName: string = path.join(dir, name) + '__tmp' + fileSuffix;
    return createSourceFile(targetName, content, ScriptTarget.ES2015, true);
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
