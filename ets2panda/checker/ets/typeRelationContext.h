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

#ifndef ES2PANDA_COMPILER_CHECKER_ETS_TYPE_RELATION_CONTEXT_H
#define ES2PANDA_COMPILER_CHECKER_ETS_TYPE_RELATION_CONTEXT_H

#include "ir/expression.h"
#include "ir/base/classDefinition.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "checker/types/type.h"
#include "checker/ETSchecker.h"

namespace panda::es2panda::checker {
class ETSChecker;

class AssignmentContext {
public:
    AssignmentContext(TypeRelation *relation, ir::Expression *node, Type *source, Type *target,
                      const lexer::SourcePosition &pos, std::initializer_list<TypeErrorMessageElement> list,
                      TypeRelationFlag flags = TypeRelationFlag::NONE)
    {
        flags_ |= ((flags & TypeRelationFlag::NO_BOXING) != 0) ? TypeRelationFlag::NONE : TypeRelationFlag::BOXING;
        flags_ |= ((flags & TypeRelationFlag::NO_UNBOXING) != 0) ? TypeRelationFlag::NONE : TypeRelationFlag::UNBOXING;
        flags_ |= ((flags & TypeRelationFlag::NO_WIDENING) != 0) ? TypeRelationFlag::NONE : TypeRelationFlag::WIDENING;

        auto *const ets_checker = relation->GetChecker()->AsETSChecker();

        if (target->IsETSArrayType() && node->IsArrayExpression()) {
            ValidateArrayTypeInitializerByElement(relation, node->AsArrayExpression(), target->AsETSArrayType());
            return;
        }

        flags_ |= flags;
        relation->SetNode(node);

        if (source->HasTypeFlag(TypeFlag::CONSTANT)) {
            flags_ |= TypeRelationFlag::NARROWING;
        }

        relation->SetFlags(flags_);

        if (!relation->IsAssignableTo(source, target)) {
            if (((flags_ & TypeRelationFlag::UNBOXING) != 0) && source->IsETSObjectType() && !relation->IsTrue()) {
                ets_checker->CheckUnboxedTypesAssignable(relation, source, target);
            }
            if (((flags_ & TypeRelationFlag::BOXING) != 0) && target->IsETSObjectType() && !relation->IsTrue()) {
                ets_checker->CheckBoxedSourceTypeAssignable(relation, source, target);
            }
        }

        if (!relation->IsTrue() && (flags_ & TypeRelationFlag::NO_THROW) == 0) {
            relation->RaiseError(list, pos);
        }

        relation->SetNode(nullptr);
        relation->SetFlags(TypeRelationFlag::NONE);
        assignable_ = true;
    }

    bool IsAssignable() const
    {
        return assignable_;
    }

    void ValidateArrayTypeInitializerByElement(TypeRelation *relation, ir::ArrayExpression *node, ETSArrayType *target);

private:
    TypeRelationFlag flags_ = TypeRelationFlag::IN_ASSIGNMENT_CONTEXT;
    bool assignable_ {false};
};

class InvocationContext {
public:
    InvocationContext(TypeRelation *relation, ir::Expression *node, Type *source, Type *target,
                      const lexer::SourcePosition &pos, std::initializer_list<TypeErrorMessageElement> list,
                      TypeRelationFlag initial_flags = TypeRelationFlag::NONE)
    {
        flags_ |=
            ((initial_flags & TypeRelationFlag::NO_BOXING) != 0) ? TypeRelationFlag::NONE : TypeRelationFlag::BOXING;
        flags_ |= ((initial_flags & TypeRelationFlag::NO_UNBOXING) != 0) ? TypeRelationFlag::NONE
                                                                         : TypeRelationFlag::UNBOXING;

        auto *const ets_checker = relation->GetChecker()->AsETSChecker();

        relation->SetNode(node);
        relation->SetFlags(flags_ | initial_flags);

        if (!relation->IsAssignableTo(source, target)) {
            if (((flags_ & TypeRelationFlag::UNBOXING) != 0U) && source->IsETSObjectType() && !relation->IsTrue()) {
                ets_checker->CheckUnboxedSourceTypeWithWideningAssignable(relation, source, target);
            }
            if (((flags_ & TypeRelationFlag::BOXING) != 0) && target->IsETSObjectType() && !relation->IsTrue()) {
                ets_checker->CheckBoxedSourceTypeAssignable(relation, source, target);
            }
        }

        relation->SetNode(nullptr);
        relation->SetFlags(TypeRelationFlag::NONE);

        if (!relation->IsTrue()) {
            if ((initial_flags & TypeRelationFlag::NO_THROW) == 0) {
                relation->RaiseError(list, pos);
            }
            return;
        }

        invocable_ = true;
    }

    bool IsInvocable() const
    {
        return invocable_;
    }

private:
    TypeRelationFlag flags_ = TypeRelationFlag::NONE;
    bool invocable_ {false};
};

class InstantiationContext {
public:
    InstantiationContext(ETSChecker *checker, ETSObjectType *type, ir::TSTypeParameterInstantiation *type_args,
                         const lexer::SourcePosition &pos)
        : checker_(checker)
    {
        ir::TSTypeParameterDeclaration *type_param_decl = nullptr;

        if (type->HasObjectFlag(ETSObjectFlags::TYPE_PARAMETER)) {
            type_param_decl = nullptr;
        } else if (type->HasObjectFlag(ETSObjectFlags::CLASS)) {
            type_param_decl = type->GetDeclNode()->AsClassDefinition()->TypeParams();
        } else if (type->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
            type_param_decl = type->GetDeclNode()->AsTSInterfaceDeclaration()->TypeParams();
        }
        if (ValidateTypeArguments(type, type_param_decl, type_args, pos)) {
            return;
        }

        InstantiateType(type, type_args);
    }

    InstantiationContext(ETSChecker *checker, ETSObjectType *type, ArenaVector<Type *> &type_args,
                         const lexer::SourcePosition &pos)
        : checker_(checker)
    {
        if (type->HasObjectFlag(ETSObjectFlags::ENUM)) {
            return;
        }
        InstantiateType(type, type_args, pos);
    }

    ETSObjectType *Result()
    {
        return result_;
    }

private:
    bool ValidateTypeArguments(ETSObjectType *type, ir::TSTypeParameterDeclaration *type_param_decl,
                               ir::TSTypeParameterInstantiation *type_args, const lexer::SourcePosition &pos);
    void InstantiateType(ETSObjectType *type, ir::TSTypeParameterInstantiation *type_args);

    void InstantiateType(ETSObjectType *type, ArenaVector<Type *> &type_arg_types, const lexer::SourcePosition &pos);
    util::StringView GetHashFromTypeArguments(ArenaVector<Type *> &type_arg_types);

    ETSChecker *checker_;
    ETSObjectType *result_ {};
};

}  // namespace panda::es2panda::checker

#endif
