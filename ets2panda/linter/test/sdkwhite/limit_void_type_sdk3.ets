/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import mainRcp,{ rcp } from '@kit.RemoteCommunicationKit';
class LI implements rcp.WriteFile{
  write(buffer: ArrayBuffer): Promise<number | void> { // Error
    throw new Error('Method not implemented.');
  }
}


const simpleDataHandler: rcp.IncomingDataCallback = (incomingData) => {
  console.log(`Received ${incomingData.byteLength} bytes of data`);
   // Error
};

interface IDataSourcePrefetching {
  prefetch(index: number): Promise<void> | void;

  cancel?(index: number): Promise<void> | void;
}
export  class LocalDataSource implements IDataSourcePrefetching {
  constructor() {}

  prefetch(index: number): void | Promise<void> {
    throw new Error("LocalDataSource Method not implemented.");
  }

  cancel(index: number): void | Promise<void> {
    throw new Error("LocalDataSource Method not implemented.");
  }
}

class L3 implements mainRcp.WriteFile {
  write(buffer: ArrayBuffer): Promise<number | void> { // error
    throw new Error('Method not implemented.');
  }
}

class L4 implements rcp.WriteFile {
  write(buffer: ArrayBuffer): Promise<number | void> { // error
    throw new Error('Method not implemented.');
  }
}