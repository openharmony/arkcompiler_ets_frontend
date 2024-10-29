/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import { A, B } from '../ets/test1'; // A报错: arkts-no-ts-import-ets
import { I, J } from '../ets/test1'; // arkts-no-ts-import-ets
import { A as A1, B as B1 } from '../ets/test1'; // arkts-no-ts-import-ets
import { I as I1, J as J1 } from '../ets/test1'; // arkts-no-ts-import-ets
import '../ets/test1'; // arkts-no-ts-import-ets
