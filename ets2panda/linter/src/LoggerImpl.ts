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

import { Logger as LoggerInterface } from '../lib/Logger';
import Logger from '../utils/logger';

export class LoggerImpl extends LoggerInterface {
  doTrace(message: string): void {
    void this;
    Logger.getLogger().trace(message);
  }

  doDebug(message: string): void {
    void this;
    Logger.getLogger().debug(message);
  }

  doInfo(message: string): void {
    void this;
    Logger.getLogger().info(message);
  }

  doWarn(message: string): void {
    void this;
    Logger.getLogger().warn(message);
  }

  doError(message: string): void {
    void this;
    Logger.getLogger().error(message);
  }
}
