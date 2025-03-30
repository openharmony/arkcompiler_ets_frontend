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
import path from 'path';
import type { IOptions } from '../configs/IOptions';
import type { IPrinterOption } from '../configs/INameObfuscationOption';
import { performanceTimeAndMemPrinter } from '../ArkObfuscator';
import { printerTimeAndMemDataConfig } from '../initialization/Initializer';

export enum EventList {
  OBFUSCATION_INITIALIZATION = 'Obfuscation initialization',
  SCAN_SYSTEMAPI = 'Scan system api',
  SCAN_SOURCEFILES = 'Scan source files',
  ALL_FILES_OBFUSCATION = 'All files obfuscation',
  OBFUSCATE = 'Obfuscate',
  CREATE_AST = 'Create AST',
  OBFUSCATE_AST = 'Obfuscate AST',
  VIRTUAL_CONSTRUCTOR_OBFUSCATION = 'Virtual constructor obfuscation',
  SHORT_HAND_OBFUSCATION = 'Shorthand obfuscation',
  REMOVE_CONSOLE = 'Remove console',
  PROPERTY_OBFUSCATION = 'Property obfuscation',
  IDENTIFIER_OBFUSCATION = 'Identifier obfuscation',
  CREATE_CHECKER = 'Create checker',
  CREATE_PROGRAM = 'Create program',
  GET_CHECKER = 'Get checker',
  SCOPE_ANALYZE = 'Scope analyze',
  CREATE_OBFUSCATED_NAMES = 'Create obfuscated names',
  OBFUSCATE_NODES = 'Obfuscate nodes',
  FILENAME_OBFUSCATION = 'Filename obfuscation',
  CREATE_PRINTER = 'Create Printer',
  GET_SOURCEMAP_GENERATOR = 'Get sourcemap generator',
  SOURCEMAP_MERGE = 'Sourcemap merge',
  CREATE_NAMECACHE = 'Create namecache',
  WRITE_FILE = 'Write file',
  RESOLVE_OBFUSCATION_CONFIGS = 'Resolve obfuscation configs',
  CONFIG_INITIALIZATION = 'Config initialization',
  WRITE_OBFUSCATION_RESULT = 'Write obfuscation result',
  GET_OBFUSCATED_CODE = 'Get obfuscated code',
  PROCESS_SOURCEMAP = 'Process sourcemap',
  GEN_CONSUMER_CONFIG = 'Gen consumer config',
  FILENAME_OBFUSCATION_INITIALIZATION = 'Filename obfuscation initialization',
  UPDATE_PARENT_NODE = 'Update parent node',
  UPDATE_IMPORT_OR_EXPORT = 'Update import or export',
  UPDATE_DYNAMIC_IMPORT = 'Update dynamic import',
  INIT_WHITELIST = 'Init whitelist',
  RENAME = 'Rename',
  HANDLE_POSITION_INFO = 'Handle position info',
  UPDATE_NAME_NODE = 'Update name node',
  RENAME_PROPERTIES = 'Rename properties',
  UPDATE_MEMBER_METHOD_NAME = 'Update member method name',
  SET_PARENT_RECURSIVE = 'Set parent recursive',
  TRANSFORM_SHORT_HAND_PROPERTY = 'Transform short hand property',
  REMOVE_VIRTUAL_CONSTRUCTOR = 'Remove virtual constructor',
  ANALYZE_SOURCE_FILE = 'Analyze sourceFile',
  ANALYZE_FUNCTION_LIKE = 'Analyze function like',
  ANALYZE_CLASS_LIKE = 'Analyze class like',
  RENAME_IDENTIFIERS = 'Rename identifiers',
  VISIT_PROPERTY_PARAMETER = 'Visit property parameter',
  GET_SYSTEM_API_CONFIGS_BY_CACHE = 'Get system api configs by cache',
}

// Time and memory performance data interface
export interface TimeAndMemInfo {
  start: number;
  startMemory: number;
  endMemory: number;
  pid: number; // Process ID
}

// Time performance data interface
export interface TimeInfo {
  name: string;
  ph: string; // Type of event
  pid: number; // Process ID
  tid: number; // Thread ID
  ts: number; // Start time
  dur: number; // Duration
}

// Memory performance data interface
export interface MemInfo {
  name: string;
  startMemory: string;
  endMemory: string;
}

const MILLISECOND_TO_MICROSECOND = 1000; // Millisecond to microsecond
const BYTE_TO_MB = 1024 * 1024; // Byte to MB
const SIG_FIGS = 3; // Significant figures
const TID = 1; // single-threaded
const END_MEMORY_INITIALIZE = 0; // Initialize the memory to zero and terminate the process
const EVENT_STACK_EMPTY_LENGTH = 0; // The length of the eventStack when it is empty
const PH = 'X'; // Type of event
const INDENTATION_SPACES = 2; // Number of indentation spaces
const TIME_PERFORMANCE_FILE_NAME = 'timePerformanceData.json'; // Time performance data file name
const MEMORY_PERFORMANCE_FILE_NAME = 'memoryPerformanceData.json'; // Memory performance data file name

export const eventListTimeAndMemValues = new Set<string>(Object.values(EventList));

export class TimeAndMemTimeTracker {
  static obfuscationCacheDir: string = ''; // Obtain the directory of the obfuscated output file
  private eventStack: Array<{ eventName: string; data: TimeAndMemInfo }> = [];
  timeDataArr: TimeInfo[] = [];
  memoryDataArr: MemInfo[] = [];

  startEvent(eventName: string): void {
    this.eventStack.push({
      eventName: eventName,
      data: {
        start: performance.now(),
        startMemory: process.memoryUsage().heapUsed,
        endMemory: END_MEMORY_INITIALIZE,
        pid: process.pid,
      },
    });
  }

  endEvent(eventName: string): void {
    if (this.eventStack.length === EVENT_STACK_EMPTY_LENGTH) {
      throw new Error(`Event stack is empty`);
    }

    const lastEvent = this.eventStack.pop();

    if (
      !eventListTimeAndMemValues.has(lastEvent.eventName) ||
      lastEvent.eventName === EventList.OBFUSCATION_INITIALIZATION ||
      lastEvent.eventName === EventList.SCAN_SOURCEFILES
    ) {
      const startMemory = lastEvent.data.startMemory / BYTE_TO_MB;
      const endMemory = process.memoryUsage().heapUsed / BYTE_TO_MB;
      this.memoryDataArr.push(this.formatMemoryPerformanceData(lastEvent.eventName, startMemory, endMemory));
    }

    if (eventListTimeAndMemValues.has(lastEvent.eventName)) {
      const timeDuration = performance.now() - lastEvent.data.start;
      this.timeDataArr.push(
        this.formatTimePerformanceData(eventName, lastEvent.data.pid, TID, lastEvent.data.start, timeDuration),
      );
    }
  }

  /**
   * Only for ut
   */
  getEventStack(): Array<{ eventName: string; data: TimeAndMemInfo }> {
    return this.eventStack;
  }

  private formatTimePerformanceData(
    eventName: string,
    pid: number,
    tid: number,
    startTime: number,
    duration: number,
  ): TimeInfo {
    const formatttedTs = startTime * MILLISECOND_TO_MICROSECOND;
    const formatttedDur = duration * MILLISECOND_TO_MICROSECOND;
    return {
      name: eventName,
      ph: PH,
      pid: pid,
      tid: tid,
      ts: formatttedTs,
      dur: formatttedDur,
    };
  }

  private formatMemoryPerformanceData(eventName: string, startMemory: number, endMemory: number): MemInfo {
    const formatttedName = path.basename(eventName);
    const formatttedStartMemory = startMemory.toFixed(SIG_FIGS) + 'MB';
    const formatttedEndMemory = endMemory.toFixed(SIG_FIGS) + 'MB';
    return {
      name: formatttedName,
      startMemory: formatttedStartMemory,
      endMemory: formatttedEndMemory,
    };
  }
}

/**
 * Initialize performance printer
 */
export function initPerformanceTimeAndMemPrinter(mCustomProfiles: IOptions): void {
  const printerConfig: IPrinterOption | undefined = mCustomProfiles.mPerformanceTimeAndMemPrinter;

  // If no performance printer configuration is provided, disable the printer and return.
  if (!printerConfig) {
    blockTimeAndMemPrinter();
    return;
  }

  // Disable performance printer if no specific printer types (files, single file) are enabled.
  const isPrinterDisabled = !(printerConfig.mFilesPrinter || printerConfig.mSingleFilePrinter);

  if (isPrinterDisabled) {
    blockTimeAndMemPrinter();
    return;
  }
}

/**
 * Disable performance printer
 */
export function blockTimeAndMemPrinter(): void {
  performanceTimeAndMemPrinter.filesPrinter = undefined;
  performanceTimeAndMemPrinter.singleFilePrinter = undefined;
}

/**
 * Clear Time&Mem performance printer
 */
export function clearTimeAndMemPrinterData(): void {
  if (performanceTimeAndMemPrinter.singleFilePrinter) {
    performanceTimeAndMemPrinter.singleFilePrinter.timeDataArr = [];
    performanceTimeAndMemPrinter.singleFilePrinter.memoryDataArr = [];
  }
  if (performanceTimeAndMemPrinter.filesPrinter) {
    performanceTimeAndMemPrinter.filesPrinter.timeDataArr = [];
    performanceTimeAndMemPrinter.filesPrinter.memoryDataArr = [];
  }
}

/**
 * Start recording singleFileForMoreTimePrinter event
 */
export function startSingleFileForMoreTimeEvent(eventName: string): void {
  if (printerTimeAndMemDataConfig.mMoreTimePrint) {
    performanceTimeAndMemPrinter.singleFilePrinter?.startEvent(eventName);
  }
}

/**
 * End recording singleFileForMoreTimePrinter event
 */
export function endSingleFileForMoreTimeEvent(eventName: string): void {
  if (printerTimeAndMemDataConfig.mMoreTimePrint) {
    performanceTimeAndMemPrinter.singleFilePrinter?.endEvent(eventName);
  }
}

/**
 * Enable timeAndMemoryPrint
 */
export function enableTimeAndMemoryPrint(): void {
  if (printerTimeAndMemDataConfig.mTimeAndMemPrinter) {
    printTimeAndMemory();
  }
}

/**
 * Print data of timeAndMemory
 */
export function printTimeAndMemory(): void {
  printTimePerformanceData();
  printMemoryPerformanceData();
}

/**
 * Print data of timePerformance
 */
export function printTimePerformanceData(): void {
  writeTimeAndMemoryPerformanceData(getTimePerformanceData(), TIME_PERFORMANCE_FILE_NAME);
}

/**
 * Print data of memoryPerformance
 */
export function printMemoryPerformanceData(): void {
  writeTimeAndMemoryPerformanceData(getMemoryPerformanceData(), MEMORY_PERFORMANCE_FILE_NAME);
}

/**
 * Write data of timeAndMemoryPerformance
 */
export async function writeTimeAndMemoryPerformanceData(data: (TimeInfo | MemInfo)[], fileName: string): Promise<void> {
  const filePath: string = path.join(TimeAndMemTimeTracker.obfuscationCacheDir, fileName);
  try {
    await fs.promises.writeFile(filePath, JSON.stringify(data, null, INDENTATION_SPACES));
  } catch (error) {
    throw new Error('Failed to write file: ' + error.message.toString());
  }
}

/**
 * Get data of obfuscationCacheDir
 */
export function getObfuscationCacheDir(projectConfig: any): void {
  if (projectConfig) {
    TimeAndMemTimeTracker.obfuscationCacheDir = projectConfig.obfuscationOptions?.obfuscationCacheDir;
  }
}

/**
 * Get data of timePerformance
 */
export function getTimePerformanceData(): TimeInfo[] {
  const singleFilePrinterTime: TimeInfo[] = performanceTimeAndMemPrinter.singleFilePrinter?.timeDataArr || [];
  const filesPrinterTime: TimeInfo[] = performanceTimeAndMemPrinter.filesPrinter?.timeDataArr || [];
  return filesPrinterTime.concat(singleFilePrinterTime);
}

/**
 * Print data of memoryPerformance
 */
export function getMemoryPerformanceData(): MemInfo[] {
  const filesPrinterMemory: MemInfo[] = performanceTimeAndMemPrinter.filesPrinter?.memoryDataArr || [];
  const singleFilePrinterMemory: MemInfo[] = performanceTimeAndMemPrinter.singleFilePrinter?.memoryDataArr || [];
  return filesPrinterMemory.concat(singleFilePrinterMemory);
}
