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

import type { LoggerInterface } from '../lib/Logger';
import Logger from '../utils/logger';

export class LoggerImpl implements LoggerInterface {
  trace(message: string): void {
    void this;
    Logger.getLogger().trace(message);
  }

  debug(message: string): void {
    void this;
    Logger.getLogger().debug(message);
  }

  info(message: string): void {
    void this;
    Logger.getLogger().info(message);
  }

  warn(message: string): void {
    void this;
    Logger.getLogger().warn(message);
  }

  error(message: string): void {
    void this;
    Logger.getLogger().error(message);
  }
}
