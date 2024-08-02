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
import { TimeTracker, TimeSumPrinter } from '../../../src/utils/PrinterUtils';
import { assert, expect } from 'chai';
import { isFileExist } from '../../../src/initialization/utils';
const sinon = require('sinon');

describe('test Cases for <PrinterUtils>.', function () {
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
        let path = 'test/ut/utils/testTimeTrackerPrint.txt';
        let message = 'start Create AST event';
        printer.setOutputPath(path);
        printer.startEvent(eventName, undefined, message);
        let content: string = fs.readFileSync(path, 'utf-8');
        const eventData = printer.getEventStack().get(eventName);
        expect(eventData?.duration).to.equal(0);
        expect(eventData?.endMemory).to.equal(0);
        expect(eventData?.memoryUsage).to.equal(0);
        assert.strictEqual(content, 'start Create AST event\n');
        fs.unlinkSync(path);
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
        assert.strictEqual(firstLine[0], 'All files obfuscation');
        assert.strictEqual(secondLine[0], 'Max time cost');
        assert.strictEqual(thirdLine[0], 'Max memory usage');
        fs.unlinkSync(path);
      });

      it('should output data for CREATE_PRINTER', () => {
        const eventName = 'Create Printer';
        const startMemory = process.memoryUsage().heapUsed;
        let path = 'test/ut/utils/demo1.txt';
        printer.setOutputPath(path);
        printer.getEventStack().set(eventName,
          { start: Date.now(), duration: 0, startMemory: startMemory, endMemory: 0, memoryUsage: 0});
        printer.endEvent(eventName);
        let content: string = fs.readFileSync(path, 'utf-8');
        const firstLine = content.split(':');
        assert.strictEqual(firstLine[0], '    Create Printer');
        fs.unlinkSync(path);
      });
    });

    describe('Tester Cases for <getCurrentEventData>.', function () {
      it('should return a string with formatted event data', () => {
        const eventName = 'test event';
        printer.getEventStack().set(eventName,
          { start: 0, duration: 10, startMemory: 1024, endMemory: 2048, memoryUsage: 1024});
        const actualOutput: string = printer.getCurrentEventData();
        const expectOutput: string = 'test event: timeCost:10.000s startMemory:0.001MB endMemory:0.002MB memoryUsage:0.001MB\n';
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
        const expectOutput = "test event1: 40.000s\ntest event2: 20.000s\n\n";
        expect(content).to.equal(expectOutput);
        fs.unlinkSync(path);
      });
    });

    describe('Tester Cases for <getCurrentEventData>.', function () {
      it('should return a string with formatted event data', () => {
        const eventName = 'test event';
        printer.getEventSum().set(eventName, 10);
        const actualOutput: string = printer.getCurrentEventData();
        const expectOutput: string = 'test event: 10.000s\n';
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
});




