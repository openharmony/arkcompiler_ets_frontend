/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import type { ProjectInfo } from '../common/type';
import type {IOptions} from '../configs/IOptions';
import type {Node, TransformerFactory} from 'typescript';

export interface TransformPlugin {
  name: string;
  order: number
  createTransformerFactory: (option: IOptions, projectInfo?: ProjectInfo) => TransformerFactory<Node>;
}

export enum TransformerOrder {
  SHORTHAND_PROPERTY_TRANSFORMER = 0,
  DISABLE_CONSOLE_TRANSFORMER = 1,
  DISABLE_HILOG_TRANSFORMER = 2,
  SIMPLIFY_TRANSFORMER = 3,
  RENAME_PROPERTIES_TRANSFORMER = 4,
  RENAME_IDENTIFIER_TRANSFORMER = 5,
  RENAME_FILE_NAME_TRANSFORMER = 6,
}