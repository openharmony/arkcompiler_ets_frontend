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

#include "destructuring.h"

#include "util/helpers.h"
#include "compiler/base/iterators.h"
#include "compiler/base/lreference.h"
#include "compiler/base/catchTable.h"
#include "compiler/core/pandagen.h"
#include "ir/base/property.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/objectExpression.h"

namespace panda::es2panda::compiler {
static void GenRestElement(PandaGen *pg, const ir::SpreadElement *rest_element,
                           const DestructuringIterator &dest_iterator, bool is_declaration)
{
    VReg array = pg->AllocReg();
    VReg index = pg->AllocReg();

    auto *next = pg->AllocLabel();
    auto *done = pg->AllocLabel();

    DestructuringRestIterator iterator(dest_iterator);

    // create left reference for rest element
    auto lref = JSLReference::Create(pg, rest_element, is_declaration);

    // create an empty array first
    pg->CreateEmptyArray(rest_element);
    pg->StoreAccumulator(rest_element, array);

    // index = 0
    pg->LoadAccumulatorInt(rest_element, 0);
    pg->StoreAccumulator(rest_element, index);

    pg->SetLabel(rest_element, next);

    iterator.Step(done);
    pg->StoreObjByValue(rest_element, array, index);

    // index++
    pg->LoadAccumulatorInt(rest_element, 1);
    pg->Binary(rest_element, lexer::TokenType::PUNCTUATOR_PLUS, index);
    pg->StoreAccumulator(rest_element, index);

    pg->Branch(rest_element, next);

    pg->SetLabel(rest_element, done);
    pg->LoadAccumulator(rest_element, array);

    lref.SetValue();
}

static void GenArray(PandaGen *pg, const ir::ArrayExpression *array)
{
    // RegScope rs(pg);
    DestructuringIterator iterator(pg, array);

    if (array->Elements().empty()) {
        iterator.Close(false);
        return;
    }

    TryContext try_ctx(pg);
    const auto &label_set = try_ctx.LabelSet();
    pg->SetLabel(array, label_set.TryBegin());

    for (const auto *element : array->Elements()) {
        RegScope ers(pg);

        if (element->IsRestElement()) {
            GenRestElement(pg, element->AsRestElement(), iterator, array->IsDeclaration());
            break;
        }

        // if a hole exist, just let the iterator step ahead
        if (element->IsOmittedExpression()) {
            iterator.Step();
            continue;
        }

        const ir::Expression *init = nullptr;
        const ir::Expression *target = element;

        if (element->IsAssignmentPattern()) {
            target = element->AsAssignmentPattern()->Left();
            init = element->AsAssignmentPattern()->Right();
        }

        auto lref = JSLReference::Create(pg, target, array->IsDeclaration());
        iterator.Step();

        if (init != nullptr) {
            auto *assign_value = pg->AllocLabel();
            auto *default_init = pg->AllocLabel();
            pg->BranchIfUndefined(element, default_init);
            pg->LoadAccumulator(element, iterator.Result());
            pg->Branch(element, assign_value);

            pg->SetLabel(element, default_init);
            init->Compile(pg);
            pg->SetLabel(element, assign_value);
        }

        lref.SetValue();
    }

    pg->SetLabel(array, label_set.TryEnd());

    // Normal completion
    pg->LoadAccumulator(array, iterator.Done());
    pg->BranchIfTrue(array, label_set.CatchEnd());
    iterator.Close(false);

    pg->Branch(array, label_set.CatchEnd());

    Label *end = pg->AllocLabel();
    pg->SetLabel(array, label_set.CatchBegin());
    pg->StoreAccumulator(array, iterator.Result());
    pg->LoadAccumulator(array, iterator.Done());

    pg->BranchIfTrue(array, end);
    pg->LoadAccumulator(array, iterator.Result());
    iterator.Close(true);
    pg->SetLabel(array, end);
    pg->LoadAccumulator(array, iterator.Result());
    pg->EmitThrow(array);
    pg->SetLabel(array, label_set.CatchEnd());
}

static std::tuple<const ir::Expression *, const ir::Expression *> GetAssignmentTarget(const ir::Property *prop_expr)
{
    const ir::Expression *init = nullptr;
    const ir::Expression *target = prop_expr->Value();

    if (target->IsAssignmentPattern()) {
        init = target->AsAssignmentPattern()->Right();
        target = target->AsAssignmentPattern()->Left();
    }

    return {init, target};
}

static void GenDefaultInitializer(PandaGen *pg, const ir::Expression *element, const ir::Expression *init)
{
    if (init == nullptr) {
        return;
    }

    RegScope rs(pg);
    VReg loaded_value = pg->AllocReg();
    pg->StoreAccumulator(element, loaded_value);

    auto *get_default = pg->AllocLabel();
    auto *store = pg->AllocLabel();

    pg->BranchIfUndefined(element, get_default);
    pg->LoadAccumulator(element, loaded_value);
    pg->Branch(element, store);

    // load default value
    pg->SetLabel(element, get_default);
    init->Compile(pg);

    pg->SetLabel(element, store);
}

static void GenObjectWithRest(PandaGen *pg, const ir::ObjectExpression *object, VReg rhs)
{
    const auto &properties = object->Properties();

    RegScope rs(pg);
    VReg prop_start = pg->NextReg();

    for (const auto *element : properties) {
        if (element->IsRestElement()) {
            RegScope rest_scope(pg);
            auto lref = JSLReference::Create(pg, element, object->IsDeclaration());
            pg->CreateObjectWithExcludedKeys(element, rhs, prop_start, properties.size() - 1);
            lref.SetValue();
            break;
        }

        VReg prop_reg = pg->AllocReg();

        RegScope prop_scope(pg);

        const ir::Property *prop_expr = element->AsProperty();
        const ir::Expression *key = prop_expr->Key();
        const auto [init, target] = GetAssignmentTarget(prop_expr);

        if (key->IsIdentifier()) {
            pg->LoadAccumulatorString(key, key->AsIdentifier()->Name());
        } else {
            key->Compile(pg);
        }

        pg->StoreAccumulator(key, prop_reg);

        auto lref = JSLReference::Create(pg, target, object->IsDeclaration());

        pg->LoadAccumulator(element, prop_reg);
        pg->LoadObjByValue(element, rhs);

        GenDefaultInitializer(pg, element, init);

        lref.SetValue();
    }
}

static void GenObject(PandaGen *pg, const ir::ObjectExpression *object, VReg rhs)
{
    const auto &properties = object->Properties();

    if (properties.empty() || properties.back()->IsRestElement()) {
        auto *not_nullish = pg->AllocLabel();

        pg->LoadAccumulator(object, rhs);
        pg->BranchIfCoercible(object, not_nullish);
        pg->ThrowObjectNonCoercible(object);

        pg->SetLabel(object, not_nullish);

        if (!properties.empty()) {
            return GenObjectWithRest(pg, object, rhs);
        }
    }

    for (const auto *element : properties) {
        RegScope prop_scope(pg);

        const ir::Property *prop_expr = element->AsProperty();
        const ir::Expression *key = prop_expr->Key();
        const auto [init, target] = GetAssignmentTarget(prop_expr);

        Operand prop_operand = pg->ToOwnPropertyKey(key, prop_expr->IsComputed());

        auto lref = JSLReference::Create(pg, target, object->IsDeclaration());

        if (std::holds_alternative<VReg>(prop_operand)) {
            pg->LoadAccumulator(element, std::get<VReg>(prop_operand));
            pg->LoadObjByValue(element, rhs);
        } else {
            pg->LoadAccumulator(element, rhs);
            pg->LoadObjProperty(element, prop_operand);
        }

        GenDefaultInitializer(pg, element, init);

        lref.SetValue();
    }
}

void Destructuring::Compile(PandaGen *pg, const ir::Expression *pattern)
{
    RegScope rs(pg);

    VReg rhs = pg->AllocReg();
    pg->StoreAccumulator(pattern, rhs);

    if (pattern->IsArrayPattern()) {
        GenArray(pg, pattern->AsArrayPattern());
    } else {
        GenObject(pg, pattern->AsObjectPattern(), rhs);
    }

    pg->LoadAccumulator(pattern, rhs);
}
}  // namespace panda::es2panda::compiler
