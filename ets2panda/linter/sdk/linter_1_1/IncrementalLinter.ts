/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import * as ts from 'typescript';

export class IncrementalLinterState {
  // @ts-expect-error : should expect method
  private readonly changedFiles: ts.Set<ts.Path> = new ts.Set<ts.Path>();
  // @ts-expect-error : should expect method
  private readonly programState: ts.ReusableBuilderProgramState;
  private readonly oldDiagnostics:
    | undefined
    // @ts-expect-error : should expect method
    | ts.ESMap<ts.Path, readonly ts.ReusableDiagnostic[] | readonly ts.Diagnostic[]>;

  constructor(builderProgram: ts.BuilderProgram, arkTSVersion?: string, compilerOptions?: ts.CompilerOptions) {
    // @ts-expect-error : should expect method
    this.programState = builderProgram.getState();
    this.oldDiagnostics = this.programState.arktsLinterDiagnosticsPerFile;
    this.programState.arktsLinterDiagnosticsPerFile = new Map();
    this.changedFiles = IncrementalLinterState.collectChangedFilesFromProgramState(
      this.programState,
      arkTSVersion,
      compilerOptions
    );
  }

  isFileChanged(srcFile: ts.SourceFile): boolean {
    // @ts-expect-error : should expect method
    return this.changedFiles.has(srcFile.resolvedPath);
  }

  getOldDiagnostics(srcFile: ts.SourceFile): ts.Diagnostic[] {
    // @ts-expect-error : should expect method
    return (this.oldDiagnostics?.get(srcFile.resolvedPath) as ts.Diagnostic[]) ?? [];
  }

  updateDiagnostics(srcFile: ts.SourceFile, newDiagnostics: ts.Diagnostic[]): void {
    // @ts-expect-error : should expect method
    this.programState.arktsLinterDiagnosticsPerFile?.set(srcFile.resolvedPath, newDiagnostics);
  }

  updateProgramStateArkTSVersion(arkTSVersion?: string): void {
    this.programState.arkTSVersion = arkTSVersion;
  }

  static emitBuildInfo(buildInfoWriteFile: ts.WriteFileCallback, builderProgram: ts.BuilderProgram): void {
    // @ts-expect-error : should expect method
    builderProgram.emitBuildInfo(buildInfoWriteFile);
  }

  private static collectChangedFilesFromProgramState(
    // @ts-expect-error : should expect method
    state: ts.ReusableBuilderProgramState,
    arkTSVersion?: string,
    compilerOptions?: ts.CompilerOptions
  ): ts.Set<ts.Path> {
    if (
      state.arkTSVersion !== arkTSVersion ||
      state.compatibleSdkVersion !== compilerOptions?.compatibleSdkVersion ||
      state.compatibleSdkVersionStage !== compilerOptions?.compatibleSdkVersionStage
    ) {
      // @ts-expect-error : should expect method
      return new ts.Set<ts.Path>(IncrementalLinterState.arrayFrom(state.fileInfos.keys()));
    }

    // @ts-expect-error : should expect method
    const changedFiles = new ts.Set<ts.Path>(state.changedFilesSet);

    /*
     * If any source file that affects global scope has been changed,
     * then process all files in project.
     */
    for (const changedFile of IncrementalLinterState.arrayFrom(changedFiles.keys())) {
      const fileInfo = state.fileInfos.get(changedFile);
      if (fileInfo?.affectsGlobalScope) {
        // @ts-expect-error : should expect method
        return new ts.Set<ts.Path>(IncrementalLinterState.arrayFrom(state.fileInfos.keys()));
      }
    }

    if (!state.referencedMap) {
      return changedFiles;
    }

    // @ts-expect-error : should expect method
    const seenPaths = new ts.Set<ts.Path>();
    const queue = IncrementalLinterState.arrayFrom(changedFiles.keys());
    while (queue.length) {
      const path = queue.pop()!;
      if (!seenPaths.has(path)) {
        seenPaths.add(path);

        // @ts-expect-error : should expect method
        queue.push(...ts.BuilderState.getReferencedByPaths(state, path));
      }
    }
    return seenPaths;
  }

  private static arrayFrom(iterator: Iterator<ts.Path>): ts.Path[] {
    const result: ts.Path[] = [];
    for (let iterResult = iterator.next(); !iterResult.done; iterResult = iterator.next()) {
      result.push(iterResult.value);
    }
    return result;
  }
}
