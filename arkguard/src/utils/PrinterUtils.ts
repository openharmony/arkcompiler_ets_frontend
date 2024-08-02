/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

export enum EventList {
  OBFUSCATION_INITIALIZATION = 'Obfuscation initialization',
  ALL_FILES_OBFUSCATION = 'All files obfuscation',
  CREATE_AST = 'Create AST',
  OBFUSCATE_AST = 'Obfuscate AST',
  VIRTUAL_CONSTRUCTOR_OBFUSCATION = 'Virtual constructor obfuscation',
  SHORT_HAND_OBFUSCATION = 'Shorthand obfuscation',
  REMOVE_CONSOLE = 'Remove console',
  PROPERTY_OBFUSCATION = 'Property obfuscation',
  IDENTIFIER_OBFUSCATION = 'Identifier obfuscation',
  CREATE_CHECKER = 'Create checker',
  SCOPE_ANALYZE = 'Scope analyze',
  CREATE_OBFUSCATED_NAMES = 'Create obfuscated names',
  OBFUSCATE_NODES = 'Obfuscate nodes',
  FILENAME_OBFUSCATION = 'Filename obfuscation',
  CREATE_PRINTER = 'Create Printer'
}

export enum EventIndentation {
  TWOSPACE = 2,
  ONESPACE = 1,
  NOSPACE = 0,
};

export const eventList = new Map<string, number>([
  [EventList.OBFUSCATION_INITIALIZATION, EventIndentation.NOSPACE],
  [EventList.ALL_FILES_OBFUSCATION, EventIndentation.NOSPACE],
  [EventList.CREATE_AST, EventIndentation.ONESPACE],
  [EventList.OBFUSCATE_AST, EventIndentation.ONESPACE],
  [EventList.VIRTUAL_CONSTRUCTOR_OBFUSCATION, EventIndentation.TWOSPACE],
  [EventList.SHORT_HAND_OBFUSCATION, EventIndentation.TWOSPACE],
  [EventList.REMOVE_CONSOLE, EventIndentation.TWOSPACE],
  [EventList.PROPERTY_OBFUSCATION, EventIndentation.TWOSPACE],
  [EventList.IDENTIFIER_OBFUSCATION, EventIndentation.TWOSPACE],
  [EventList.CREATE_CHECKER, EventIndentation.TWOSPACE],
  [EventList.SCOPE_ANALYZE, EventIndentation.TWOSPACE],
  [EventList.CREATE_OBFUSCATED_NAMES, EventIndentation.TWOSPACE],
  [EventList.OBFUSCATE_NODES, EventIndentation.TWOSPACE],
  [EventList.FILENAME_OBFUSCATION, EventIndentation.TWOSPACE],
  [EventList.CREATE_PRINTER, EventIndentation.ONESPACE],
]);

export interface TimeAndMemInfo {
  start: number;
  duration: number;
  startMemory: number;
  endMemory: number;
  memoryUsage: number;
}

const MILLISECOND_TO_SECOND = 1000;
const BYTE_TO_MB = 1024 * 1024;
const SIG_FIGS = 3;// 有效数字位数
const INDENT = '    ';

abstract class BasePrinter {
  protected outputPath: string | undefined;

  protected abstract getCurrentEventData(): string;

  constructor(outputPath: string = "") {
    this.outputPath = outputPath;
  }

  setOutputPath(outputPath: string | undefined) {
    this.outputPath = outputPath;
  }

  print(message: string): void {
    if (this.outputPath && this.outputPath !== "") {
      fs.appendFileSync(`${this.outputPath}`, message + "\n");
    } else {
      console.log(message);
    }
  }

  outputData(): void {
    const eventData = this.getCurrentEventData();
    this.print(eventData);
  }

  // Only used for ut
  getOutputPath(): string {
    return this.outputPath;
  }
}

export class TimeTracker extends BasePrinter {
  private eventStack: Map<string, TimeAndMemInfo> = new Map<string, TimeAndMemInfo>();
  private filesTimeSum: number = 0;
  private maxTimeUsage = 0;
  private maxTimeFile = "";
  private maxMemoryUsage: number = 0;
  private maxMemoryFile: string = '';

  startEvent(eventName: string, timeSumPrinter?: TimeSumPrinter, currentFile?: string): void {
    this.eventStack.set(eventName, {start: Date.now(), duration: 0, startMemory: process.memoryUsage().heapUsed,
      endMemory: 0, memoryUsage: 0});
    timeSumPrinter?.addEventDuration(eventName, 0);
    if (eventName === EventList.CREATE_AST) {
      this.print(currentFile);
    }
  }

  endEvent(eventName: string, timeSumPrinter?: TimeSumPrinter, isFilesPrinter?: boolean): void {
    if (!this.eventStack.get(eventName)) {
      throw new Error(`Event "${eventName}" not started`);
    }

    const eventStartTime = this.eventStack.get(eventName).start;
    const duration = (Date.now() - eventStartTime)/MILLISECOND_TO_SECOND;
    const eventEndMemory = process.memoryUsage().heapUsed;
    const eventStartMemory = this.eventStack.get(eventName).startMemory;
    const memoryUsage = eventEndMemory - eventStartMemory;

    if (isFilesPrinter) {
      this.filesTimeSum += duration;

      if (duration > this.maxTimeUsage) {
        this.maxTimeUsage = duration;
        this.maxTimeFile = eventName;
      }

      if (eventStartMemory > this.maxMemoryUsage) {
        this.maxMemoryUsage = eventStartMemory;
        this.maxMemoryFile = eventName;
      }

      if (eventEndMemory > this.maxMemoryUsage) {
        this.maxMemoryUsage = eventEndMemory;
        this.maxMemoryFile = eventName;
      }
    }

    this.eventStack.get(eventName).duration = duration;
    this.eventStack.get(eventName).endMemory = eventEndMemory;
    this.eventStack.get(eventName).memoryUsage = memoryUsage;

    timeSumPrinter?.addEventDuration(eventName, duration);

    if ((eventName === EventList.ALL_FILES_OBFUSCATION)) {
      this.eventStack.get(eventName).duration = this.filesTimeSum;
      this.outputData();
      const maxTimeUsage = this.maxTimeUsage.toFixed(SIG_FIGS);
      const maxMemoryUsage = (this.maxMemoryUsage/BYTE_TO_MB).toFixed(SIG_FIGS);
      this.print(`Max time cost: ${this.maxTimeFile}: ${maxTimeUsage}s`)
      this.print(`Max memory usage: ${this.maxMemoryFile}: ${maxMemoryUsage}MB\n`)
    }

    if ((eventName === EventList.CREATE_PRINTER)) {
      this.outputData();
    }
  }

  getCurrentEventData(): string {
    let eventData = "";
    for (const eventName of this.eventStack.keys()) {
      let depth = eventList.get(eventName)?? 0;
      let eventInfo = this.eventStack.get(eventName);
      const duration = eventInfo.duration;
      const startMemory = eventInfo.startMemory/BYTE_TO_MB;
      const endMemory = eventInfo.endMemory/BYTE_TO_MB;
      const memoryUsage = eventInfo.memoryUsage/BYTE_TO_MB;
      eventData += this.formatEvent(eventName, duration, startMemory, endMemory, memoryUsage, depth);
    }
    return eventData;
  }

  private formatEvent(eventName: string, duration: number, startMemory: number, endMemory: number,
    memoryUsage: number, depth: number): string {
    const indent = INDENT.repeat(depth);
    const formattedDuration = duration.toFixed(SIG_FIGS) + 's';
    const formatttedStartMemory = startMemory.toFixed(SIG_FIGS) + 'MB';
    const formatttedEndMemory  = endMemory.toFixed(SIG_FIGS) + 'MB';
    const formatttedMemoryUsage  = memoryUsage.toFixed(SIG_FIGS) + 'MB';
    return `${indent}${eventName}: timeCost:${formattedDuration} startMemory:${formatttedStartMemory} `+
    `endMemory:${formatttedEndMemory} memoryUsage:${formatttedMemoryUsage}\n`;
  }

  // Only used for ut
  getEventStack(): Map<string, TimeAndMemInfo> {
    return this.eventStack;
  }

  getFilesTimeSum(): number {
    return this.filesTimeSum;
  }

  getMaxTimeUsage(): number {
    return this.maxTimeUsage;
  }

  getMaxTimeFile(): string {
    return this.maxTimeFile;
  }

  getMaxMemoryUsage(): number {
    return this.maxMemoryUsage;
  }

  getMaxMemoryFile(): string {
    return this.maxMemoryFile;
  }
}

export class TimeSumPrinter extends BasePrinter {
  private eventSum: Map<string, number> = new Map<string, number>();
  addEventDuration(eventName: string, duration: number): void {
    const currentValue = this.eventSum.get(eventName) ?? 0;
    this.eventSum.set(eventName, currentValue + duration);
  }

  summarizeEventDuration(): void {
    const eventData = this.getCurrentEventData();
    this.print(eventData);
  }

  getCurrentEventData(): string {
    let eventData = "";
    for (const eventName of this.eventSum.keys()) {
      let depth = eventList.get(eventName)?? 0;
      const duration = this.eventSum.get(eventName);
      eventData += this.formatEvent(eventName, duration, depth);
    }
    return eventData;
  }

  private formatEvent(eventName: string, duration: number, depth: number): string {
    const indent = INDENT.repeat(depth);
    const formattedDuration = duration.toFixed(SIG_FIGS) + 's';
    return `${indent}${eventName}: ${formattedDuration}\n`;
  }

  getEventSum(): Map<string, number> {
    return this.eventSum;
  }
}