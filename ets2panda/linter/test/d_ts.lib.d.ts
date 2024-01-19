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

import { Margin, Length } from "./d_ts.lib2";
import { AsyncCallback, AsyncCallback2 } from "./d_ts.lib2";

// issue 13041
export interface InsightIntent {
  intentEntityInfo: {
    entityId: string;
    entityName: string;
    [key: string]: Object;
  }
}

// issue 13043
declare function margin<T>(value: Margin | Length): T;

// issue 13048
declare class WindowsStage {
  loadContent(path: string, callback: AsyncCallback<void>): void;
  loadContent2(path: string, callback: AsyncCallback2<void>): void;
}

export interface Indexed {
  [x: string]: number;
}

type TypeLiteral = {
  a: number,
  b: string
}