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
namespace AA {
    export class B<T>{}
}

let fecthResult = await checkAsyncDelay(async (): Promise< AA.B<string> > => {
    if (!this.photoAccessHelper) {
        return undefined;
    }
    return await this.photoAccessHelper.getAssets(options);
}, 'getPhotoAssetByUri --> getAssets');

/* @@? 19:25 Error TypeError: Unresolved reference checkAsyncDelay  */
/* @@? 19:25 Error TypeError: 'await' expressions require Promise object as argument.  */
/* @@? 20:10 Error TypeError: Bad operand type, the type of the operand must be boolean type.  */
/* @@? 21:16 Error TypeError: Type 'undefined' is not compatible with the enclosing method's return type 'Promise<B<String>>'  */
/* @@? 23:18 Error TypeError: 'await' expressions require Promise object as argument.  */
/* @@? 1:1 Error TypeError: Cannot reference 'this' in this context.  */
