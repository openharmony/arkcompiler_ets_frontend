/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_CHECKER_TS_DESTRUCTURING_CONTEXT_H
#define ES2PANDA_CHECKER_TS_DESTRUCTURING_CONTEXT_H

#include "checker/TSchecker.h"
#include "ir/expression.h"

#include <macros.h>

namespace panda::es2panda::ir {
class Expression;
class SpreadElement;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::checker {
class Type;

class DestructuringContext {
public:
    DestructuringContext(TSChecker *checker, ir::Expression *id, bool in_assignment, bool convert_tuple_to_array,
                         ir::TypeNode *type_annotation, ir::Expression *initializer)
        : checker_(checker), id_(id), in_assignment_(in_assignment), convert_tuple_to_array_(convert_tuple_to_array)
    {
        Prepare(type_annotation, initializer, id->Start());
    }

    void SetInferredType(Type *type)
    {
        inferred_type_ = type;
    }

    void SetSignatureInfo(SignatureInfo *info)
    {
        signature_info_ = info;
    }

    Type *InferredType()
    {
        return inferred_type_;
    }

    void ValidateObjectLiteralType(ObjectType *obj_type, ir::ObjectExpression *obj_pattern);
    void HandleDestructuringAssignment(ir::Identifier *ident, Type *inferred_type, Type *default_type);
    void HandleAssignmentPattern(ir::AssignmentExpression *assignment_pattern, Type *inferred_type,
                                 bool validate_default);
    void SetInferredTypeForVariable(binder::Variable *var, Type *inferred_type, const lexer::SourcePosition &loc);
    void Prepare(ir::TypeNode *type_annotation, ir::Expression *initializer, const lexer::SourcePosition &loc);

    DEFAULT_COPY_SEMANTIC(DestructuringContext);
    DEFAULT_MOVE_SEMANTIC(DestructuringContext);
    ~DestructuringContext() = default;

    virtual void Start() = 0;
    virtual void ValidateInferredType() = 0;
    virtual Type *NextInferredType([[maybe_unused]] const util::StringView &search_name, bool throw_error) = 0;
    virtual void HandleRest(ir::SpreadElement *rest) = 0;
    virtual Type *GetRestType([[maybe_unused]] const lexer::SourcePosition &loc) = 0;
    virtual Type *ConvertTupleTypeToArrayTypeIfNecessary(ir::AstNode *node, Type *type) = 0;

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    TSChecker *checker_;
    ir::Expression *id_;
    bool in_assignment_;
    bool convert_tuple_to_array_;
    Type *inferred_type_ {};
    SignatureInfo *signature_info_ {};
    bool validate_object_pattern_initializer_ {true};
    bool validate_type_annotation_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class ArrayDestructuringContext : public DestructuringContext {
public:
    ArrayDestructuringContext(TSChecker *checker, ir::Expression *id, bool in_assignment, bool convert_tuple_to_array,
                              ir::TypeNode *type_annotation, ir::Expression *initializer)
        : DestructuringContext(checker, id, in_assignment, convert_tuple_to_array, type_annotation, initializer)
    {
    }

    Type *GetTypeFromTupleByIndex(TupleType *tuple);
    Type *CreateArrayTypeForRest(UnionType *inferred_type);
    Type *CreateTupleTypeForRest(TupleType *tuple);
    void SetRemainingParameterTypes();

    void Start() override;
    void ValidateInferredType() override;
    Type *NextInferredType([[maybe_unused]] const util::StringView &search_name, bool throw_error) override;
    void HandleRest(ir::SpreadElement *rest) override;
    Type *GetRestType([[maybe_unused]] const lexer::SourcePosition &loc) override;
    Type *ConvertTupleTypeToArrayTypeIfNecessary(ir::AstNode *node, Type *type) override;

private:
    uint32_t index_ {0};
};

class ObjectDestructuringContext : public DestructuringContext {
public:
    ObjectDestructuringContext(TSChecker *checker, ir::Expression *id, bool in_assignment, bool convert_tuple_to_array,
                               ir::TypeNode *type_annotation, ir::Expression *initializer)
        : DestructuringContext(checker, id, in_assignment, convert_tuple_to_array, type_annotation, initializer)
    {
    }

    Type *CreateObjectTypeForRest(ObjectType *obj_type);

    void Start() override;
    void ValidateInferredType() override;
    Type *NextInferredType([[maybe_unused]] const util::StringView &search_name, bool throw_error) override;
    void HandleRest(ir::SpreadElement *rest) override;
    Type *GetRestType([[maybe_unused]] const lexer::SourcePosition &loc) override;
    Type *ConvertTupleTypeToArrayTypeIfNecessary(ir::AstNode *node, Type *type) override;
};
}  // namespace panda::es2panda::checker

#endif
