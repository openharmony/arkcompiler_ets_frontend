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
import mocha from 'mocha';
import { TimeAndMemInfo, TimeSumPrinter, TimeTracker, initPerformancePrinter } from '../../../src/utils/PrinterUtils';
import { assert, expect } from 'chai';
import { isFileExist } from '../../../src/initialization/utils';
import {
  blockPrinter,
  endFilesEvent,
  endSingleFileEvent,
  performancePrinter,
  printTimeSumData,
  printTimeSumInfo,
  startFilesEvent,
  startSingleFileEvent
} from '../../../src/ArkObfuscator';
import type { IOptions } from '../../../src/configs/IOptions';
const sinon = require('sinon');
const DEFAULT_DURATION = 1; // Default time duration

describe('test Cases for <PrinterUtils>.', function () {
  beforeEach(() => {
    performancePrinter.filesPrinter = new TimeTracker();
    performancePrinter.singleFilePrinter = new TimeTracker();
    performancePrinter.timeSumPrinter = new TimeSumPrinter();
  });

  describe('Tester Cases for <TimeTracker>.', function () {
    let printer: TimeTracker;

    beforeEach(() => {
      printer = new TimeTracker();
    })

    describe('Tester Cases for <setOutputPath>.', function () {
      /** test for setOutputPath */
      it('Tester: <setOutputPath> case for TimeTracker#setOutputPath', function () {
        let path = 'test/ut/utils/demo1.txt';
        printer.setOutputPath(path);
        let content: string = printer.getOutputPath();
        assert.strictEqual(content, path);
      });
    });

    describe('Tester Cases for <print>.', function () {
      /** test for print */
      it('Tester: <available outputPath> case for TimeTracker#print', function () {
        let path = 'test/ut/utils/testTimeTrackerPrint.txt';
        printer.setOutputPath(path);
        printer.print('available outputPath case');
        let content: string = fs.readFileSync(path, 'utf-8');
        assert.strictEqual(content, 'available outputPath case\n');
        fs.unlinkSync(path);
      });

      it('Tester: <unavailable outputPath> case for TimeTracker#print', function () {
        let path = 'test/ut/utils/demo2.txt';
        let message = 'unavailable outputPath case';
        var spy = sinon.spy(console, 'log');
        printer.print(message);
        assert(spy.calledWith(message), message);
        assert.strictEqual(isFileExist(path), false);
        spy.restore();
      });
    });

    describe('Tester Cases for <disablePrinter>.', function () {
      /** test for print */
      it('Tester: <empty output> case for TimeTracker#disablePrinter', function () {
        const eventName = 'All files obfuscation';
        let path = 'test/ut/utils/demo1.txt';
        printer.setOutputPath(path);
        printer.disablePrinter();
        printer.getEventStack().set(eventName, { start: 0, duration: 0, startMemory: 0, endMemory: 0, memoryUsage: 0});
        printer.endEvent(eventName);
        let content: string = fs.readFileSync(path, 'utf-8');
        const lines = content.split('\n');
        const firstLine = lines[0].split(':');
        const secondLine = lines[1].split(':');
        const thirdLine = lines[2].split(':');
        assert.strictEqual(firstLine[0], 'Obfuscation time cost');
        assert.strictEqual(secondLine[0], 'Max time cost of single file');
        assert.strictEqual(thirdLine[0], 'Max memory usage of single file');
        fs.unlinkSync(path);
      });
    });

    describe('Tester Cases for <startEvent>.', function () {
      /** test for startEvent */
      it('Tester: <start test event> case for TimeTracker#startEvent', function () {
        let eventName = 'test event';
        let path = 'test/ut/utils/testTimeTrackerPrint.txt';
        let message = 'start test event';
        printer.setOutputPath(path);
        printer.startEvent(eventName, undefined, message);
        const eventData = printer.getEventStack().get(eventName);
        expect(eventData?.duration).to.equal(0);
        expect(eventData?.endMemory).to.equal(0);
        expect(eventData?.memoryUsage).to.equal(0);
        assert.strictEqual(isFileExist(path), false);
      });

      it('Tester: <start create ast event> case for TimeTracker#startEvent', function () {
        let eventName = 'Create AST';
        printer.startEvent(eventName, undefined);
        const eventData = printer.getEventStack().get(eventName);
        expect(eventData?.duration).to.equal(0);
        expect(eventData?.endMemory).to.equal(0);
        expect(eventData?.memoryUsage).to.equal(0);
      });
    });

    describe('Tester Cases for <endEvent>.', function () {
      /** test for endEvent */
      it('should throw an error if the event has not started', function () {
        let eventName = '';
        let path = 'test/ut/utils/demo1.txt';
        printer.setOutputPath(path);
        printer.startEvent('test event');
        expect(() => printer.endEvent(eventName)).to.throw(`Event "${eventName}" not started`);
      });

      it('should calculate duration and memory usage correctly', () => {
        const eventName = 'test Event';
        printer.getEventStack().set(eventName,
          { start: 0, duration: 0, startMemory: 0, endMemory: 0, memoryUsage: 0});
        printer.endEvent(eventName);
        const eventData = printer.getEventStack().get(eventName);
        expect(eventData?.duration).to.not.equal(0);
        expect(eventData?.endMemory).to.not.equal(0);
        expect(eventData?.memoryUsage).to.not.equal(0);
      });

      it('should update filesTimeSum and maxTimeUsage when isFilesPrinter is true', () => {
        const eventName = 'file Event';
        const startMemory = process.memoryUsage().heapUsed;
        printer.getEventStack().set(eventName,
          { start: 0, duration: 0, startMemory: startMemory, endMemory: 0, memoryUsage: 0});
        printer.endEvent(eventName, undefined, true);
        expect(printer.getFilesTimeSum()).to.not.equal(0);
        expect(printer.getMaxTimeUsage()).to.not.equal(0);
        expect(printer.getMaxTimeFile()).to.equal(eventName);
      });

      it('should update maxMemoryUsage and maxMemoryFile when isFilesPrinter is true', () => {
        const eventName = 'file Event';
        const startTime = Date.now();
        printer.getEventStack().set(eventName,
          { start: startTime, duration: 0, startMemory: 0, endMemory: 0, memoryUsage: 0});
        printer.endEvent(eventName, undefined, true);
        expect(printer.getMaxMemoryUsage()).to.not.equal(0);
        expect(printer.getMaxMemoryFile()).to.equal(eventName);
      });

      it('should output data and print max time and memory usage for ALL_FILES_OBFUSCATION', () => {
        const eventName = 'All files obfuscation';
        let path = 'test/ut/utils/demo1.txt';
        printer.setOutputPath(path);
        printer.getEventStack().set(eventName, { start: 0, duration: 0, startMemory: 0, endMemory: 0, memoryUsage: 0});
        printer.endEvent(eventName);
        let content: string = fs.readFileSync(path, 'utf-8');
        const lines = content.split('\n');
        const firstLine = lines[0].split(':');
        const secondLine = lines[2].split(':');
        const thirdLine = lines[3].split(':');
        const fourthLine = lines[4].split(':');
        assert.strictEqual(firstLine[0], '    All files obfuscation');
        assert.strictEqual(secondLine[0], 'Obfuscation time cost');
        assert.strictEqual(thirdLine[0], 'Max time cost of single file');
        assert.strictEqual(fourthLine[0], 'Max memory usage of single file');
        fs.unlinkSync(path);
      });

      it('should output data for CREATE_PRINTER', () => {
        const eventName = 'Create Printer';
        const startMemory = process.memoryUsage().heapUsed;
        let path = 'test/ut/utils/demo1.txt';
        printer.setOutputPath(path);
        printer.getEventStack().set(eventName,
          { start: Date.now(), duration: 0, startMemory: startMemory, endMemory: 0, memoryUsage: 0});
        printer.endEvent(eventName, undefined, false, true);
        let content: string = fs.readFileSync(path, 'utf-8');
        const firstLine = content.split(':');
        assert.strictEqual(firstLine[0], '        Create Printer');
        fs.unlinkSync(path);
      });

      it('should get totalTime', () => {
        let path = 'test/ut/utils/demo1.txt';
        printer.setOutputPath(path);
        const eventName1 = 'Obfuscation initialization';
        const eventName2 = 'All files obfuscation';
        let testFile = 'test/ut/utils/testFile.ts';
        printer.getEventStack().set(eventName1,
          { start: Date.now(), duration: 0, startMemory: 0, endMemory: 0, memoryUsage: 0});
        printer.getEventStack().set(eventName2,
          { start: Date.now(), duration: 0, startMemory: 0, endMemory: 0, memoryUsage: 0, filePath: testFile});
        printer.endEvent(eventName2);
        let content: string = fs.readFileSync(path, 'utf-8');
        const lines = content.split('\n');
        const firstLine = lines[0].split(':');
        const secondLine = lines[1].split(':');
        const thirdLine = lines[2].split(':');
        assert.strictEqual(firstLine[0], 'Obfuscation time cost');
        assert.strictEqual(secondLine[0], '    Obfuscation initialization');
        assert.strictEqual(thirdLine[0], 'test/ut/utils/testFile.ts');
        fs.unlinkSync(path);
      });
    });

    describe('Tester Cases for <getCurrentEventData>.', function () {
      it('should return a string with formatted event data', () => {
        const eventName = 'test event';
        printer.getEventStack().set(eventName,
          { start: 0, duration: 10, startMemory: 1024, endMemory: 2048, memoryUsage: 1024});
        const actualOutput: string = printer.getCurrentEventData();
        const expectOutput: string = '        test event: timeCost:10.000 s startMemory:0.001MB endMemory:0.002MB memoryUsage:0.001MB\n';
        expect(actualOutput).to.equal(expectOutput);
      });
    });

    describe('Tester Cases for <getEventStack>', () => {

      it('should return the event stack', () => {
        printer.startEvent('test event');
        const eventStack = printer.getEventStack();
        expect(eventStack).to.have.keys(['test event']);
        expect(eventStack.get('test event')?.start).to.closeTo(Date.now(), 10);
        expect(eventStack.get('test event')?.duration).to.equal(0);
        expect(eventStack.get('test event')?.endMemory).to.equal(0);
        expect(eventStack.get('test event')?.memoryUsage).to.equal(0);
      });
    });
  });


  describe('Tester Cases for <TimeSumPrinter>.', function () {
    let printer: TimeSumPrinter;

    beforeEach(() => {
      printer = new TimeSumPrinter();
    })

    describe('Tester Cases for <addEventDuration>.', function () {
      /** test for addEventDuration */
      it('should add duration to the event sum', function () {
        printer.addEventDuration('test event1', 10);
        printer.addEventDuration('test event2', 20);
        printer.addEventDuration('test event1', 30);
        const event1Duration = printer.getEventSum().get('test event1');
        const event2Duration = printer.getEventSum().get('test event2');
        expect(event1Duration).to.equal(40);
        expect(event2Duration).to.equal(20);
      });
    });

    describe('Tester Cases for <summarizeEventDuration>.', function () {
      /** test for summarizeEventDuration */
      it('should print the summarized event data', function () {
        let path = 'test/ut/utils/demo1.txt';
        printer.setOutputPath(path);
        printer.addEventDuration('test event1', 10);
        printer.addEventDuration('test event2', 20);
        printer.addEventDuration('test event1', 30);
        printer.summarizeEventDuration();
        let content: string = fs.readFileSync(path, 'utf-8');
        const expectOutput = "test event1: 40.000 s\ntest event2: 20.000 s\n\n";
        expect(content).to.equal(expectOutput);
        fs.unlinkSync(path);
      });
    });

    describe('Tester Cases for <getCurrentEventData>.', function () {
      it('should return a string with formatted event data', () => {
        const eventName = 'test event';
        printer.getEventSum().set(eventName, 10);
        const actualOutput: string = printer.getCurrentEventData();
        const expectOutput: string = 'test event: 10.000 s\n';
        expect(actualOutput).to.equal(expectOutput);
      });
    });

    describe('Tester Cases for <getEventSum>', () => {
      it('should return the event sum', () => {
        printer.addEventDuration('test event', 10);
        const eventSum = printer.getEventSum();
        expect(eventSum).to.have.keys(['test event']);
        expect(eventSum.get('test event')).to.equal(10);
      });
    });
  });

  describe('Tester Cases for <initPerformancePrinter>', () => {
    it('Printer config is not set', () => {
      let mCustomProfiles: IOptions = {};
      initPerformancePrinter(mCustomProfiles);
      expect(performancePrinter.filesPrinter === undefined).to.be.true;
      expect(performancePrinter.singleFilePrinter === undefined).to.be.true;
      expect(performancePrinter.timeSumPrinter === undefined).to.be.true;
    });

    it('None of printers is enabled', () => {
      let mCustomProfiles: IOptions = {
        mPerformancePrinter: {
          mFilesPrinter: false,
          mSingleFilePrinter: false,
          mSumPrinter: false
        }
      };
      initPerformancePrinter(mCustomProfiles);
      expect(performancePrinter.filesPrinter === undefined).to.be.true;
      expect(performancePrinter.singleFilePrinter === undefined).to.be.true;
      expect(performancePrinter.timeSumPrinter === undefined).to.be.true;
    });

    it('disable mFilesPrinter', () => {
      let mCustomProfiles: IOptions = {
        mPerformancePrinter: {
          mFilesPrinter: false,
          mSingleFilePrinter: true,
          mSumPrinter: true,
          mOutputPath: './log.txt'
        }
      };
      initPerformancePrinter(mCustomProfiles);
      expect(performancePrinter.filesPrinter?.isEnabled()).to.be.false;
      expect(performancePrinter.singleFilePrinter?.isEnabled()).to.be.true;
      expect(performancePrinter.timeSumPrinter?.isEnabled()).to.be.true;
    });

    it('disable mSingleFilePrinter', () => {
      let mCustomProfiles: IOptions = {
        mPerformancePrinter: {
          mFilesPrinter: true,
          mSingleFilePrinter: false,
          mSumPrinter: true,
          mOutputPath: './log.txt'
        }
      };
      initPerformancePrinter(mCustomProfiles);
      expect(performancePrinter.filesPrinter?.isEnabled()).to.be.true;
      expect(performancePrinter.singleFilePrinter?.isEnabled()).to.be.false;
      expect(performancePrinter.timeSumPrinter?.isEnabled()).to.be.true;
    });

    it('disable mSumPrinter', () => {
      let mCustomProfiles: IOptions = {
        mPerformancePrinter: {
          mFilesPrinter: true,
          mSingleFilePrinter: true,
          mSumPrinter: false,
          mOutputPath: './log.txt'
        }
      };
      initPerformancePrinter(mCustomProfiles);
      expect(performancePrinter.filesPrinter?.isEnabled()).to.be.true;
      expect(performancePrinter.singleFilePrinter?.isEnabled()).to.be.true;
      expect(performancePrinter.timeSumPrinter?.isEnabled()).to.be.false;
    });
  });

  describe('Tester Cases for <blockPrinter>', () => {
    it('should disable all printers', () => {
      blockPrinter();
      expect(performancePrinter.filesPrinter === undefined).to.be.true;
      expect(performancePrinter.singleFilePrinter === undefined).to.be.true;
      expect(performancePrinter.timeSumPrinter === undefined).to.be.true;
    });
  });

  describe('Tester Cases for <startSingleFileEvent>', () => {
    it('start a singleFile event', () => {
      let eventName: string = 'newEvent';
      let filePath: string = 'currentFile.ts';
      startSingleFileEvent(eventName, undefined, filePath);
      const eventStack: Map<string, TimeAndMemInfo> | undefined = performancePrinter.singleFilePrinter?.getEventStack();
      let targetFilePath: string | undefined = eventStack?.get(eventName)?.filePath;
      expect(targetFilePath === filePath).to.be.true;
    });
  });

  describe('Tester Cases for <endSingleFileEvent>', () => {
    it('end a singleFile event', () => {
      let eventName: string = 'newEvent';
      let filePath: string = 'currentFile.ts';
      startSingleFileEvent(eventName, undefined, filePath);
      endSingleFileEvent(eventName, undefined, false, false);
      const eventStack: Map<string, TimeAndMemInfo> | undefined = performancePrinter.singleFilePrinter?.getEventStack();
      let targetFilePath: string | undefined = eventStack?.get(eventName)?.filePath;
      let memoryUsage: number | undefined = eventStack?.get(eventName)?.memoryUsage;
      expect(targetFilePath === filePath).to.be.true;
      expect(memoryUsage !== 0).to.be.true;
    });
  });

  describe('Tester Cases for <startFilesEvent>', () => {
    it('start a files event', () => {
      let eventName: string = 'filesEvent';
      let filePath: string = 'currentFile.ts';
      startFilesEvent(eventName, undefined, filePath);
      const eventStack: Map<string, TimeAndMemInfo> | undefined = performancePrinter.filesPrinter?.getEventStack();
      let targetFilePath: string | undefined = eventStack?.get(eventName)?.filePath;
      let startTime: number | undefined = eventStack?.get(eventName)?.start;
      expect(targetFilePath === filePath).to.be.true;
      expect(startTime !== 0).to.be.true;
    });
  });

  describe('Tester Cases for <endFilesEvent>', () => {
    it('end a files event', () => {
      let eventName: string = 'filesEvent';
      let filePath: string = 'currentFile.ts';
      startFilesEvent(eventName, undefined, filePath);
      endFilesEvent(eventName, undefined, false, false);
      const eventStack: Map<string, TimeAndMemInfo> | undefined = performancePrinter.filesPrinter?.getEventStack();
      let targetFilePath: string | undefined = eventStack?.get(eventName)?.filePath;
      let memoryUsage: number | undefined = eventStack?.get(eventName)?.memoryUsage;
      expect(targetFilePath === filePath).to.be.true;
      expect(memoryUsage !== 0).to.be.true;
    });
  });

  describe('Tester Cases for <printTimeSumInfo>', () => {
    it('print input info of timeSumPrinter', () => {
      let info: string = 'Info of timeSumPrinter';
      let outputPath: string = 'test/ut/utils/outPutFile.txt';
      performancePrinter.timeSumPrinter?.setOutputPath(outputPath);
      printTimeSumInfo(info);
      let content: string = fs.readFileSync(outputPath, 'utf-8');
      expect(content === info + '\n').to.be.true;
      fs.unlinkSync(outputPath);
    });

    it('timeSumPrinter is undefined', () => {
      let info: string = 'Info of timeSumPrinter';
      let outputPath: string = 'test/ut/utils/outPutFile.txt';
      performancePrinter.timeSumPrinter?.setOutputPath(outputPath);
      performancePrinter.timeSumPrinter = undefined;
      printTimeSumInfo(info);
      expect(fs.existsSync(outputPath)).to.be.false;
    });
  });

  describe('Tester Cases for <printTimeSumData>', () => {
    it('print data of timeSumPrinter', () => {
      let outputPath: string = 'test/ut/utils/outPutFile.txt';
      performancePrinter.timeSumPrinter?.setOutputPath(outputPath);
      performancePrinter.timeSumPrinter?.addEventDuration('event1', DEFAULT_DURATION);
      performancePrinter.timeSumPrinter?.addEventDuration('event1', DEFAULT_DURATION);
      performancePrinter.timeSumPrinter?.addEventDuration('event2', DEFAULT_DURATION);
      performancePrinter.timeSumPrinter?.addEventDuration('event2', DEFAULT_DURATION);
      printTimeSumData();
      let content: string = fs.readFileSync(outputPath, 'utf-8');
      expect(content === 'event1: 2.000 s\nevent2: 2.000 s\n\n').to.be.true;
      fs.unlinkSync(outputPath);
    });

    it('timeSumPrinter is undefined', () => {
      let outputPath: string = 'test/ut/utils/outPutFile.txt';
      performancePrinter.timeSumPrinter?.setOutputPath(outputPath);
      performancePrinter.timeSumPrinter?.addEventDuration('event1', DEFAULT_DURATION);
      performancePrinter.timeSumPrinter?.addEventDuration('event1', DEFAULT_DURATION);
      performancePrinter.timeSumPrinter?.addEventDuration('event2', DEFAULT_DURATION);
      performancePrinter.timeSumPrinter?.addEventDuration('event2', DEFAULT_DURATION);
      performancePrinter.timeSumPrinter = undefined;
      printTimeSumData();
      expect(fs.existsSync(outputPath)).to.be.false;
    });
  });
});




