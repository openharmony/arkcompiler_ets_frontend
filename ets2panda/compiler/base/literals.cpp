/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "literals.h"

#include "compiler/core/pandagen.h"
#include "ir/base/templateElement.h"
#include "ir/expressions/taggedTemplateExpression.h"
#include "ir/expressions/templateLiteral.h"

namespace panda::es2panda::compiler {
void Literals::GetTemplateObject(PandaGen *pg, const ir::TaggedTemplateExpression *lit)
{
    RegScope rs(pg);
    VReg template_arg = pg->AllocReg();
    VReg index_reg = pg->AllocReg();
    VReg raw_arr = pg->AllocReg();
    VReg cooked_arr = pg->AllocReg();

    const ir::TemplateLiteral *template_lit = lit->Quasi();

    pg->CreateEmptyArray(template_lit);
    pg->StoreAccumulator(template_lit, raw_arr);

    pg->CreateEmptyArray(template_lit);
    pg->StoreAccumulator(template_lit, cooked_arr);

    size_t elem_index = 0;

    for (const auto *element : template_lit->Quasis()) {
        pg->LoadAccumulatorInt(element, elem_index);
        pg->StoreAccumulator(element, index_reg);

        pg->LoadAccumulatorString(element, element->Raw());
        pg->StoreObjByValue(element, raw_arr, index_reg);

        pg->LoadAccumulatorString(element, element->Cooked());
        pg->StoreObjByValue(element, cooked_arr, index_reg);

        elem_index++;
    }

    pg->CreateEmptyArray(lit);
    pg->StoreAccumulator(lit, template_arg);

    elem_index = 0;
    pg->LoadAccumulatorInt(lit, elem_index);
    pg->StoreAccumulator(lit, index_reg);

    pg->LoadAccumulator(lit, raw_arr);
    pg->StoreObjByValue(lit, template_arg, index_reg);

    elem_index++;
    pg->LoadAccumulatorInt(lit, elem_index);
    pg->StoreAccumulator(lit, index_reg);

    pg->LoadAccumulator(lit, cooked_arr);
    pg->StoreObjByValue(lit, template_arg, index_reg);

    pg->GetTemplateObject(lit, template_arg);
}
}  // namespace panda::es2panda::compiler
