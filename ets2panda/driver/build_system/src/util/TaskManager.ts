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

import { fork, ChildProcess } from 'child_process';
import * as os from 'os';

import { DEFAULT_WOKER_NUMS } from '../pre_define';
import { createTaskId } from './utils';
import { LogData, Logger } from '../logger';

export interface Task<T> {
  id: string;
  payload: T;
  resolve: (result: true) => void;
  reject: (error: Object) => void;
}

export interface WorkerInfo {
  worker: ChildProcess;
  id: number;
  currentTaskId?: string;
  isKilled: boolean;
}

type OnWorkerExitCallback<T> = (
  workerInfo: WorkerInfo,
  code: number | null,
  runningTasks: Map<string, Task<T>>
) => void;

interface WorkerMessage {
  id: string;
  success: boolean;
  error?: LogData;
}

export class TaskManager<T> {
  private workers: WorkerInfo[] = [];
  private idleWorkers: WorkerInfo[] = [];
  private taskQueue: Task<T>[] = [];
  private runningTasks = new Map<string, Task<T>>();
  private maxWorkers = DEFAULT_WOKER_NUMS;
  private workerPath: string;
  private onWorkerExit: OnWorkerExitCallback<T>;

  constructor(workerPath: string, onWorkerExit: OnWorkerExitCallback<T>, maxWorkers?: number) {
    const cpuCount = Math.max(os.cpus().length - 1, 1);

    this.workerPath = workerPath;
    this.onWorkerExit = onWorkerExit;

    if (maxWorkers !== undefined) {
      this.maxWorkers = Math.min(maxWorkers, cpuCount);
    } else {
      this.maxWorkers = DEFAULT_WOKER_NUMS;
    }
  }

  public startWorkers(): void {
    for (let i = 0; i < this.maxWorkers; i++) {
      const worker = fork(this.workerPath, [], {
        stdio: ['inherit', 'inherit', 'inherit', 'ipc']
      });

      const workerInfo: WorkerInfo = { worker, id: i, isKilled: false };

      worker.on('message', (message: WorkerMessage) => {
        const { id, success, error } = message;
        if (!success) {
          this.shutdown();
          Logger.getInstance().printErrorAndExit(error!);
        }
        const task = this.runningTasks.get(id);
        task?.resolve(true);
        this.runningTasks.delete(id);
        workerInfo.currentTaskId = undefined;
        this.idleWorkers.push(workerInfo);
        this.dispatchNext();
      });

      worker.on('exit', (code) => {
        if (workerInfo.isKilled) {
          return;
        }
        if (this.onWorkerExit) {
          this.onWorkerExit(workerInfo, code, this.runningTasks);
          return;
        }
      });

      this.workers.push(workerInfo);
      this.idleWorkers.push(workerInfo);
    }

    this.dispatchNext();
  }


  private dispatchNext(): void {
    while (this.taskQueue.length > 0 && this.idleWorkers.length > 0) {
      const task = this.taskQueue.shift()!;
      const workerInfo = this.idleWorkers.shift()!;

      this.runningTasks.set(task.id, task);
      workerInfo.currentTaskId = task.id;

      workerInfo.worker.send({ id: task.id, payload: task.payload });
    }
  }

  public submitTask(payload: T): Promise<true> {
    return new Promise<true>((resolve, reject) => {
      const task: Task<T> = {
        id: createTaskId(),
        payload,
        resolve,
        reject,
      };
      this.taskQueue.push(task);
      this.dispatchNext();
    });
  }

  public async shutdown(): Promise<void> {
    await Promise.all(this.workers.map((workerInfo) =>
      new Promise<void>((res) => {
        workerInfo.isKilled = true;
        workerInfo.worker.kill();
        res();
      })
    ));
    this.workers = [];
    this.idleWorkers = [];
    this.runningTasks.clear();
    this.taskQueue = [];
  }
}