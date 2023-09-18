/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


function makeBox<T>(value: T) {
    return { value };
};

const makeStringBox = makeBox<string>;  // (value: string) => { value: string }
const stringBox = makeStringBox('abc');  // { value: string }

type StringBoxMaker = typeof makeBox<string>;  // (value: string) => { value: string }
type BoxFunc<T> = typeof makeBox<T>;  // (value: T) => { value: T }
type Box<T> = ReturnType<typeof makeBox<T>>;  // { value: T }
type StringBox = Box<string>;  // { value: string }