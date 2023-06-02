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

// Test scenario: just modify anonymous function's content, no addition or deletion of anonymous functions in hotfix,
// es2abc will keep the name in patch.abc same as base.abc.

// in hotfix patch, its name keeps
// as #9041263686285634408# other than #5678037123100335536# for first anonymous function
// as #8070990178058117078# other than #14150848034378622959# for second anonymous function
function A () {
    print("A2");
    (()=>{
        print("anonymous: 2");
    })();
    (()=>{
        print("anonymous: 4");
    })();
}
