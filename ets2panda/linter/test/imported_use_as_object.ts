/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

import { OuterC, OuterN, OuterE } from './imported_use_as_object_module'

class InnerC { }
namespace InnerN { let x = 1; }
enum InnerE { e = 1 }

function foo1(f: Function) { }
function foo2(o: Object) { }

foo1(() => OuterC);
foo2(OuterC);
typeof OuterC;

foo1(() => OuterN);
foo2(OuterN);
typeof OuterN;

foo1(() => OuterE);
foo2(OuterE);
typeof OuterE;

foo1(() => InnerC);
foo2(InnerC);
typeof InnerC;

foo1(() => InnerN);
foo2(InnerN);
typeof InnerN;

foo1(() => InnerE);
foo2(InnerE);
typeof InnerE;

OuterE[OuterE.e];
InnerE[InnerE.e];
