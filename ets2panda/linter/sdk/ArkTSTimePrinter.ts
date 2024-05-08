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

export enum TimePhase {
  START = 'start',
  GET_PROGRAM = 'getProgram(not ArkTSLinter)',
  GET_REVERSE_STRICT_BUILDER_PROGRAM = 'getReverseStrictBuilderProgram',
  UPDATE_ERROR_FILE = 'updateErrorFile',
  INIT = 'init',
  STRICT_PROGRAM_GET_SEMANTIC_DIAGNOSTICS = 'strictProgramGetSemanticDiagnostics',
  STRICT_PROGRAM_GET_SYNTACTIC_DIAGNOSTICS = 'strictProgramGetSyntacticDiagnostics',
  NON_STRICT_PROGRAM_GET_SEMANTIC_DIAGNOSTICS = 'nonStrictProgramGetSemanticDiagnostics',
  NON_STRICT_PROGRAM_GET_SYNTACTIC_DIAGNOSTICS = 'nonStrictProgramGetSyntacticDiagnostics',
  GET_TSC_DIAGNOSTICS = 'getTscDiagnostics',
  EMIT_BUILD_INFO = 'emitBuildInfo',
  LINT = 'lint'
}

const MILLISECOND_TO_SECOND = 1000.0;

export class ArkTSLinterTimePrinter {
  private static instance?: ArkTSLinterTimePrinter;
  private arkTSTimePrintSwitch: boolean;
  private readonly timeMap = new Map<string, number>();

  private constructor(ArkTSTimePrintSwitch: boolean = false) {
    this.arkTSTimePrintSwitch = ArkTSTimePrintSwitch;
  }

  static getInstance(): ArkTSLinterTimePrinter {
    if (!ArkTSLinterTimePrinter.instance) {
      ArkTSLinterTimePrinter.instance = new ArkTSLinterTimePrinter();
    }
    return ArkTSLinterTimePrinter.instance;
  }

  static destroyInstance(): void {
    ArkTSLinterTimePrinter.instance = undefined;
  }

  setArkTSTimePrintSwitch(arkTSTimePrintSwitch: boolean): void {
    this.arkTSTimePrintSwitch = arkTSTimePrintSwitch;
  }

  appendTime(key: string): void {
    if (this.arkTSTimePrintSwitch) {
      this.timeMap.set(key, Date.now());
    }
  }

  // eslint-disable-next-line class-methods-use-this
  private formatMapAsTable(map: Map<string, number>): string {
    if (!map.has(TimePhase.START)) {
      return 'ArkTSLinterTimePrinter: START phase is not exist!';
    }
    let maxKeyLength = 0;
    let lastVal = 0;
    let sum = 0;
    const printMap = new Map(map);
    printMap.forEach((value, key) => {
      maxKeyLength = Math.max(maxKeyLength, key.toString().length);
      if (key !== TimePhase.START) {
        const relativeVal = value - lastVal;
        if (key !== TimePhase.GET_PROGRAM) {
          sum += relativeVal;
        }
        printMap.set(key, relativeVal / MILLISECOND_TO_SECOND);
      }
      lastVal = value;
    });
    printMap.set('total', sum / MILLISECOND_TO_SECOND);

    let table = '';
    printMap.forEach((value, key) => {
      if (key !== TimePhase.START) {
        const paddedKey = key.toString().padEnd(maxKeyLength, ' ');
        table += `${paddedKey} | ${value.toString()}\n`;
      }
    });
    const header = `${'Phase'.padEnd(maxKeyLength, ' ')} | Time(seconds)\n`;
    const FIXLENGTH = ('Phase' + 'Time').length;
    const separator = '-'.repeat(maxKeyLength + FIXLENGTH) + '\n';
    return `${header}${separator}${table}`;
  }

  printTimes(): void {
    if (this.arkTSTimePrintSwitch) {
      const formattedMap = this.formatMapAsTable(this.timeMap);
      console.log(formattedMap);
    }
  }
}
