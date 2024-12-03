/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

export interface LoggerInterface {
  trace: (message: string) => void;
  debug: (message: string) => void;
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
}

export class Logger {
  static init(instance: LoggerInterface): void {
    this.instance_ = instance;
  }

  static trace(message: string): void {
    this.getInstance().trace(message);
  }

  static debug(message: string): void {
    this.getInstance().debug(message);
  }

  static info(message: string): void {
    this.getInstance().info(message);
  }

  static warn(message: string): void {
    this.getInstance().warn(message);
  }

  static error(message: string): void {
    this.getInstance().error(message);
  }

  private static getInstance(): LoggerInterface {
    if (!this.instance_) {
      throw new Error('Not initialized');
    }
    return this.instance_;
  }

  private static instance_?: LoggerInterface;
}
