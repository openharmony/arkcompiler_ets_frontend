/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

export abstract class Logger {
  static init(instance: Logger): void {
    this.instance_ = instance;
  }

  static trace(message: string): void {
    this.getInstance().doTrace(message);
  }

  static debug(message: string): void {
    this.getInstance().doDebug(message);
  }

  static info(message: string): void {
    this.getInstance().doInfo(message);
  }

  static warn(message: string): void {
    this.getInstance().doWarn(message);
  }

  static error(message: string): void {
    this.getInstance().doError(message);
  }

  protected abstract doTrace(message: string): void;
  protected abstract doDebug(message: string): void;
  protected abstract doInfo(message: string): void;
  protected abstract doWarn(message: string): void;
  protected abstract doError(message: string): void;

  private static getInstance(): Logger {
    if (!this.instance_) {
      throw new Error('Not initialized');
    }
    return this.instance_;
  }

  private static instance_?: Logger;
}
