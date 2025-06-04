/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

type T0 = {
  field: any;
};

const f0 = (o: T0) => delete o.field;

type T1 = {
  field: unknown;
};

const f1 = (o: T1) => delete o.field;

type T2 = {
  field: never;
};

const f2 = (o: T2) => delete o.field;

type T3 = {
  field?: number;
};

const f3 = (o: T3) => delete o.field;

type T4 = {
  field: number;
};

const f4 = (o: T4) => delete o.field;
