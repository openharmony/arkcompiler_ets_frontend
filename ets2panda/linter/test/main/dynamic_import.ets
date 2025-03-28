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

async function getZipFile(name: string, files: File[]): Promise<File> {
  const zipUtil = await import('create-zip-file');
  const zipContents = zipUtil.getContentAsBlob(files);
  return new File(zipContents, name);
}

import { Data } from './file'

function main(): void {
  import('./file').then((m) => {
    console.log(m.Data.name)
  })
}

import('./file').then((m) => {
  console.log(m.Data.name)
})

declare type EllipseShape = import('../api/@ohos.arkui.shape').EllipseShape;

type myClass = import('har1').HarClass;

type myClass = typeof import('har1');