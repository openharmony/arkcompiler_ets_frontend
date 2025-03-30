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
import {
  TimeAndMemTimeTracker,
  clearTimeAndMemPrinterData,
  enableTimeAndMemoryPrint,
  endSingleFileForMoreTimeEvent,
  getObfuscationCacheDir,
  getMemoryPerformanceData,
  getTimePerformanceData,
  initPerformanceTimeAndMemPrinter,
  startSingleFileForMoreTimeEvent,
  writeTimeAndMemoryPerformanceData,
} from '../../../src/utils/PrinterTimeAndMemUtils';
import { expect } from 'chai';
import { performanceTimeAndMemPrinter } from '../../../src/ArkObfuscator';
import type { IOptions } from '../../../src/configs/IOptions';
import { printerTimeAndMemDataConfig } from '../../../src/initialization/Initializer';

describe('test Cases for <PrinterTimAndMemUtils>.', function () {
  beforeEach(() => {
    performanceTimeAndMemPrinter.filesPrinter = new TimeAndMemTimeTracker();
    performanceTimeAndMemPrinter.singleFilePrinter = new TimeAndMemTimeTracker();
  });

  describe('Tester Cases for <TimeTimeAndMemTracker>.', function () {
    let printer: TimeAndMemTimeTracker;

    beforeEach(() => {
      printer = new TimeAndMemTimeTracker();
    });

    describe('Tester Cases for <startEvent>', () => {
      /** test for startEvent */
      it('Tester: <start test event> case for TimeTimeAndMemTracker#startEvent', () => {
        const eventName = 'test event';
        printer.startEvent(eventName);
        const eventStack = printer.getEventStack();
        const event = eventStack.find((e) => e.eventName === eventName);
        expect(event?.data.endMemory).to.equal(0);
      });
    });

    describe('Tester Cases for <endEvent>', () => {
      /** test for endEvent */
      it('should throw an error if the event has not started', function () {
        printer.startEvent('testEvent');
        printer.endEvent('testEvent');
        expect(() => printer.endEvent('unstartedEvent')).to.throw(`Event stack is empty`);
      });
    });
  });

  describe('Tester Cases for <initPerformanceTimeAndMemPrinter>', () => {
    it('Printer config is not set', () => {
      const mCustomProfiles: IOptions = {};
      initPerformanceTimeAndMemPrinter(mCustomProfiles);
      expect(performanceTimeAndMemPrinter.filesPrinter).to.be.undefined;
      expect(performanceTimeAndMemPrinter.singleFilePrinter).to.be.undefined;
    });

    it('Printer config is set all false', () => {
      const mCustomProfiles: IOptions = {
        mPerformanceTimeAndMemPrinter: {
          mFilesPrinter: false,
          mSingleFilePrinter: false,
        },
      };
      initPerformanceTimeAndMemPrinter(mCustomProfiles);
      expect(performanceTimeAndMemPrinter.filesPrinter).to.be.undefined;
      expect(performanceTimeAndMemPrinter.singleFilePrinter).to.be.undefined;
    });

    it('Printer config is set not all false', () => {
      const mCustomProfiles: IOptions = {
        mPerformanceTimeAndMemPrinter: {
          mFilesPrinter: false,
          mSingleFilePrinter: true,
        },
      };
      initPerformanceTimeAndMemPrinter(mCustomProfiles);
      expect(performanceTimeAndMemPrinter.filesPrinter).to.not.be.undefined;
      expect(performanceTimeAndMemPrinter.singleFilePrinter).to.not.be.undefined;
    });
  });

  describe('Tester Cases for <clearTimeAndMemPrinterData>', () => {
    it('start a clearTimeAndMemPrinterData event', () => {
      if (performanceTimeAndMemPrinter.filesPrinter) {
        performanceTimeAndMemPrinter.filesPrinter.timeDataArr.push({
          name: 'test',
          ph: 'X',
          pid: 1,
          tid: 1,
          ts: 5,
          dur: 5,
        });
        performanceTimeAndMemPrinter.filesPrinter.memoryDataArr.push({
          name: 'test',
          startMemory: '5MB',
          endMemory: '5MB',
        });
      }
      if (performanceTimeAndMemPrinter.singleFilePrinter) {
        performanceTimeAndMemPrinter.singleFilePrinter.timeDataArr.push({
          name: 'test',
          ph: 'X',
          pid: 1,
          tid: 1,
          ts: 5,
          dur: 5,
        });
        performanceTimeAndMemPrinter.singleFilePrinter.memoryDataArr.push({
          name: 'test',
          startMemory: '5MB',
          endMemory: '5MB',
        });
      }

      clearTimeAndMemPrinterData();

      expect(performanceTimeAndMemPrinter.filesPrinter?.timeDataArr.length).to.equal(0);
      expect(performanceTimeAndMemPrinter.filesPrinter?.memoryDataArr.length).to.equal(0);
      expect(performanceTimeAndMemPrinter.singleFilePrinter?.timeDataArr.length).to.equal(0);
      expect(performanceTimeAndMemPrinter.singleFilePrinter?.memoryDataArr.length).to.equal(0);
    });

    it('start a clearTimeAndMemPrinterData event is not set', () => {
      performanceTimeAndMemPrinter.filesPrinter = undefined;
      performanceTimeAndMemPrinter.singleFilePrinter = undefined;
      clearTimeAndMemPrinterData();
      expect(performanceTimeAndMemPrinter.filesPrinter === undefined).to.be.true;
      expect(performanceTimeAndMemPrinter.singleFilePrinter === undefined).to.be.true;
    });
  });

  describe('Tester Cases for <startSingleFileForMoreTimeEvent>', () => {
    it('start a singleFile event for more timeEvent when mMoreTimePrint is true', () => {
      if (!performanceTimeAndMemPrinter.singleFilePrinter) {
        performanceTimeAndMemPrinter.singleFilePrinter = new TimeAndMemTimeTracker();
      }
      const eventName = 'test event';
      printerTimeAndMemDataConfig.mMoreTimePrint = true;
      startSingleFileForMoreTimeEvent(eventName);
      const eventStack = performanceTimeAndMemPrinter.singleFilePrinter?.getEventStack();
      const event = eventStack!.find((e) => e.eventName === eventName);
      expect(event?.eventName).to.be.equal('test event');
    });

    it('start a singleFile event for more timeEvent when mMoreTimePrint is false', () => {
      const eventName = 'test event';
      printerTimeAndMemDataConfig.mMoreTimePrint = false;
      startSingleFileForMoreTimeEvent(eventName);
      const eventStack = performanceTimeAndMemPrinter.singleFilePrinter?.getEventStack();
      const event = eventStack?.find((e) => e.eventName === eventName);
      expect(event).to.be.undefined;
    });

    it('start a singleFile event for more timeEvent when performanceTimeAndMemPrinter.singleFilePrinter is undefined', () => {
      const eventName = 'test event';
      printerTimeAndMemDataConfig.mMoreTimePrint = true;
      performanceTimeAndMemPrinter.singleFilePrinter = undefined;
      expect(() => startSingleFileForMoreTimeEvent(eventName)).to.not.throw;
    });
  });

  describe('Tester Cases for <endSingleFileForMoreTimeEvent>', () => {
    it('end a singleFile event for more timeEvent', async () => {
      if (!performanceTimeAndMemPrinter.singleFilePrinter) {
        performanceTimeAndMemPrinter.singleFilePrinter = new TimeAndMemTimeTracker();
      }
      const eventName = 'test event';
      printerTimeAndMemDataConfig.mMoreTimePrint = true;
      startSingleFileForMoreTimeEvent(eventName);

      const eventStackBeforeEnd = performanceTimeAndMemPrinter.singleFilePrinter!.getEventStack();
      const eventBeforeEnd = eventStackBeforeEnd.find((e) => e.eventName === eventName);

      expect(eventBeforeEnd?.data.start).to.be.greaterThan(0);

      endSingleFileForMoreTimeEvent(eventName);

      const eventStackAfterEnd = performanceTimeAndMemPrinter.singleFilePrinter!.getEventStack();
      expect(eventStackAfterEnd.length).to.equal(0);
    });

    it('start a singleFile event for more timeEvent when performanceTimeAndMemPrinter.singleFilePrinter is undefined', () => {
      const eventName = 'test event';
      printerTimeAndMemDataConfig.mMoreTimePrint = true;
      performanceTimeAndMemPrinter.singleFilePrinter = undefined;
      expect(() => endSingleFileForMoreTimeEvent(eventName)).to.not.throw;
    });
  });

  describe('Tester Cases for <enableTimeAndMemoryPrint>', () => {
    const testCacheDir = path.join(__dirname, 'test-cache');
    const timePerformanceFilePath = path.join(testCacheDir, 'timePerformanceData.json');
    const memoryPerformanceFilePath = path.join(testCacheDir, 'memoryPerformanceData.json');

    beforeEach(() => {
      if (!fs.existsSync(testCacheDir)) {
        fs.mkdirSync(testCacheDir, { recursive: true });
      }
      if (fs.existsSync(timePerformanceFilePath)) {
        fs.unlinkSync(timePerformanceFilePath);
      }
      if (fs.existsSync(memoryPerformanceFilePath)) {
        fs.unlinkSync(memoryPerformanceFilePath);
      }

      TimeAndMemTimeTracker.obfuscationCacheDir = testCacheDir;

      if (performanceTimeAndMemPrinter.singleFilePrinter) {
        performanceTimeAndMemPrinter.singleFilePrinter.timeDataArr = [];
        performanceTimeAndMemPrinter.singleFilePrinter.memoryDataArr = [];
      }

      if (performanceTimeAndMemPrinter.filesPrinter) {
        performanceTimeAndMemPrinter.filesPrinter.timeDataArr = [];
        performanceTimeAndMemPrinter.filesPrinter.memoryDataArr = [];
      }
    });

    afterEach(() => {
      if (fs.existsSync(timePerformanceFilePath)) {
        fs.unlinkSync(timePerformanceFilePath);
      }
      if (fs.existsSync(memoryPerformanceFilePath)) {
        fs.unlinkSync(memoryPerformanceFilePath);
      }
    });

    it('should not print time and memory data when mTimeAndMemPrinter is false', () => {
      printerTimeAndMemDataConfig.mTimeAndMemPrinter = false;

      enableTimeAndMemoryPrint();

      expect(fs.existsSync(timePerformanceFilePath)).to.be.false;
      expect(fs.existsSync(memoryPerformanceFilePath)).to.be.false;
    });

    it('should print time and memory data when mTimeAndMemPrinter is true', async () => {
      printerTimeAndMemDataConfig.mTimeAndMemPrinter = true;

      performanceTimeAndMemPrinter.singleFilePrinter = new TimeAndMemTimeTracker();
      performanceTimeAndMemPrinter.singleFilePrinter.timeDataArr.push({
        name: 'Test Event',
        ph: 'X',
        pid: 1,
        tid: 1,
        ts: 1000,
        dur: 500,
      });
      performanceTimeAndMemPrinter.singleFilePrinter.memoryDataArr.push({
        name: 'Test Event',
        startMemory: '10MB',
        endMemory: '15MB',
      });

      await enableTimeAndMemoryPrint();

      expect(fs.existsSync(timePerformanceFilePath)).to.be.true;
      expect(fs.existsSync(memoryPerformanceFilePath)).to.be.true;
    });
  });

  describe('Tester Cases for <writeTimeAndMemoryPerformanceData>', () => {
    it('Write file error', () => {
      const data = [
        {
          'name': 'BreakpointConstants.ts',
          'startMemory': '318.945MB',
          'endMemory': '320.114MB',
        },
      ];
      const fileName = '';
      expect(writeTimeAndMemoryPerformanceData(data, fileName)).to.be.throw;
    });
  });

  describe('Tester Cases for <getObfuscationCacheDir>', () => {
    it('get obfuscation and cache dir when cacheDir is exited', () => {
      const projectConfig = {
        obfuscationOptions: {
          obfuscationCacheDir: 'test/',
        },
      };
      getObfuscationCacheDir(projectConfig);
      expect(TimeAndMemTimeTracker.obfuscationCacheDir).to.equal('test/');
    });

    it('get obfuscation and cache dir when obfuscationOptions is undefined', () => {
      const projectConfig = {
        obfuscationOptions: undefined,
      };
      getObfuscationCacheDir(projectConfig);
      expect(TimeAndMemTimeTracker.obfuscationCacheDir).to.be.undefined;
    });
  });

  describe('Tester Cases for <getTimePerformanceData>', () => {
    it('get time performance data', () => {
      performanceTimeAndMemPrinter.filesPrinter = undefined;
      performanceTimeAndMemPrinter.singleFilePrinter = undefined;
      const array = getTimePerformanceData();
      expect(array.length === 0).to.be.true;
    });
  });

  describe('Tester Cases for <getMemoryPerformanceData>', () => {
    it('get memory performance data', () => {
      performanceTimeAndMemPrinter.filesPrinter = undefined;
      performanceTimeAndMemPrinter.singleFilePrinter = undefined;
      const array = getMemoryPerformanceData();
      expect(array.length === 0).to.be.true;
    });
  });
});
