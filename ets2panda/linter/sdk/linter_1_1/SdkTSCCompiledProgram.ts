/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, softwareP
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type * as ts from 'typescript';
import { ArkTSLinterTimePrinter, TimePhase } from '../ArkTSTimePrinter';
import type { TSCCompiledProgram } from '../../lib/ts-diagnostics/TSCCompiledProgram';
import { getStrictDiagnostics } from './SdkTypeScriptDiagnosticsExtractor';

export class SdkTSCCompiledProgram implements TSCCompiledProgram {
  private readonly builerProgram: ts.BuilderProgram;

  constructor(builerProgram: ts.BuilderProgram) {
    this.builerProgram = builerProgram;
  }

  getProgram(): ts.Program {
    return this.builerProgram.getProgram();
  }

  getBuilderProgram(): ts.BuilderProgram {
    return this.builerProgram;
  }

  getStrictDiagnostics(fileName: string): ts.Diagnostic[] {
    return getStrictDiagnostics(this.getBuilderProgram(), fileName);
  }

  /**
   * Updates all diagnostics in TSC compilation program after the incremental build.
   */
  updateCompilationDiagnostics(): void {
    this.builerProgram.getSemanticDiagnostics();
    const timePrinterInstance = ArkTSLinterTimePrinter.getInstance();
    timePrinterInstance.appendTime(TimePhase.NON_STRICT_PROGRAM_GET_SEMANTIC_DIAGNOSTICS);
    this.builerProgram.getSyntacticDiagnostics();
    timePrinterInstance.appendTime(TimePhase.NON_STRICT_PROGRAM_GET_SYNTACTIC_DIAGNOSTICS);
    this.builerProgram.builderProgramForLinter?.getSemanticDiagnostics();
    timePrinterInstance.appendTime(TimePhase.STRICT_PROGRAM_GET_SEMANTIC_DIAGNOSTICS);
  }
}
