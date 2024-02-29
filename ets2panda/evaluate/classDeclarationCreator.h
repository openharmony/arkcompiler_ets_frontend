/**
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

#ifndef ES2PANDA_COMPILER_DEBUGGER_EVALUATE_CLASS_DECLARATION_CREATOR_H
#define ES2PANDA_COMPILER_DEBUGGER_EVALUATE_CLASS_DECLARATION_CREATOR_H

#include "evaluate/nonRecursiveIrChecker.h"

#include "ir/astNodeFlags.h"
#include "util/ustring.h"

#include "libpandabase/mem/arena_allocator.h"

namespace ark::es2panda::checker {
class ETSChecker;
class ETSObjectType;
class Type;
}  // namespace ark::es2panda::checker

namespace ark::es2panda::ir {
class AstNode;
class BlockStatement;
class ClassDeclaration;
class ClassProperty;
class Expression;
class Identifier;
class MethodDefinition;
class Statement;
class TypeNode;
class ReturnStatement;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::parser {
class Program;
}  // namespace ark::es2panda::parser

namespace ark::panda_file {
class ClassDataAccessor;
class MethodDataAccessor;
}  // namespace ark::panda_file

namespace ark::es2panda::evaluate {

// Help to create class declaration using information obtained from given .abc file
class ClassDeclarationCreator {
public:
    NO_COPY_SEMANTIC(ClassDeclarationCreator);
    NO_MOVE_SEMANTIC(ClassDeclarationCreator);

    explicit ClassDeclarationCreator(checker::ETSChecker *checker, NonRecursiveIrChecker &irChecker);
    ~ClassDeclarationCreator() = default;

    /**
     * @brief Create coherent AST for class declaration
     * @param identName class name
     * @param cda data for class recreation
     * @param program compiler program corresponding to original application's class declaration file
     * Returns non-null.
     */
    // TODO: may create properties lazily in order to reduce dependencies burden.
    ir::ClassDeclaration *CreateClassDeclaration(const util::StringView &identName, panda_file::ClassDataAccessor &cda,
                                                 parser::Program *program);

    /**
     * @brief Create property's AST
     * Returns non-null. Callers must set parent of the returned node.
     */
    ir::ClassProperty *CreateClassProperty(std::string_view name, ir::TypeNode *type, ir::ModifierFlags modifiers);

    /**
     * @brief Create method's AST
     * Returns non-null. Callers must set parent of the returned node.
     */
    ir::AstNode *CreateClassMethod(panda_file::MethodDataAccessor &mda);

private:
    using IrMethodBuilder =
        std::function<void(ArenaVector<ir::Statement *> *, ArenaVector<ir::Expression *> *, ir::TypeNode **)>;
    using IrClassBuilder = std::function<void(ArenaVector<ir::AstNode *> *)>;

private:
    ArenaVector<ir::TypeNode *> GetFunctionParameters(panda_file::MethodDataAccessor &mda);

    ir::ReturnStatement *CreateTypedReturnStatement(ir::TypeNode *type);

    void CreateClassBody(ArenaVector<ir::AstNode *> *classBody, panda_file::ClassDataAccessor &cda);

    void CreateFieldsProperties(ArenaVector<ir::AstNode *> *classBody, panda_file::ClassDataAccessor &cda);

    void CreateFunctionProperties(ArenaVector<ir::AstNode *> *classBody, panda_file::ClassDataAccessor &cda);

    ir::AstNode *CreateIrClassMethod(util::StringView name, ir::ModifierFlags modifierFlags,
                                     const IrMethodBuilder &builder, bool isConstructor);

    ir::MethodDefinition *CreateIrMethod(ir::Identifier *id, ir::BlockStatement *body, ir::TypeNode *returnType,
                                         ArenaVector<ir::Expression *> &params, ir::ModifierFlags modifierFlags);

    ir::AstNode *CreateIrConstructor(ir::Identifier *id, ir::BlockStatement *body, ir::TypeNode *returnType,
                                     ArenaVector<ir::Expression *> &params, ir::ModifierFlags modifierFlags);

    ir::ClassDeclaration *BuildIrClass(util::StringView name, const IrClassBuilder &builder, parser::Program *program);

    ArenaAllocator *Allocator();

private:
    checker::ETSChecker *checker_ {nullptr};
    NonRecursiveIrChecker &irChecker_;
};

}  // namespace ark::es2panda::evaluate

#endif  // ES2PANDA_COMPILER_DEBUGGER_EVALUATE_CLASS_DECLARATION_CREATOR_H