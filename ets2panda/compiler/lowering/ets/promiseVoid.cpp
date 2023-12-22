/**
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

#include "promiseVoid.h"
#include "checker/ETSchecker.h"
#include "checker/checker.h"
#include "compiler/core/compilerContext.h"
#include "generated/signatures.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/returnStatement.h"
#include "ir/typeNode.h"
#include "lexer/token/sourceLocation.h"
#include "ir/astNode.h"
#include "ir/statements/blockStatement.h"
#include "util/ustring.h"

namespace panda::es2panda::compiler {

std::string_view PromiseVoidLowering::Name()
{
    static std::string const NAME = "promise-void";
    return NAME;
}

static ir::BlockStatement *HandleAsyncScriptFunctionBody(checker::ETSChecker *checker, ir::BlockStatement *body)
{
    (void)checker;
    body->TransformChildrenRecursively([checker](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsReturnStatement()) {
            auto *return_stmt = ast->AsReturnStatement();
            const auto *arg = return_stmt->Argument();
            if (arg == nullptr) {
                auto *void_id =
                    checker->AllocNode<ir::Identifier>(compiler::Signatures::VOID_OBJECT, checker->Allocator());
                const auto &return_loc = return_stmt->Range();
                void_id->SetRange({return_loc.end, return_loc.end});
                return_stmt->SetArgument(void_id);
            }
        }
        return ast;
    });
    return body;
}

static void SetRangeRecursively(ir::TypeNode *node, const lexer::SourceRange &loc)
{
    node->SetRange(loc);
    node->TransformChildrenRecursively([loc](ir::AstNode *ast) -> ir::AstNode * {
        ast->SetRange(loc);
        return ast;
    });
}

static ir::TypeNode *CreatePromiseVoidType(checker::ETSChecker *checker, const lexer::SourceRange &loc)
{
    auto *void_param = [checker]() {
        auto params_vector = ArenaVector<ir::TypeNode *>(checker->Allocator()->Adapter());
        auto *void_id =
            checker->AllocNode<ir::Identifier>(compiler::Signatures::BUILTIN_VOID_CLASS, checker->Allocator());
        void_id->SetReference();
        auto *part = checker->AllocNode<ir::ETSTypeReferencePart>(void_id);
        params_vector.push_back(checker->AllocNode<ir::ETSTypeReference>(part));
        auto *params = checker->AllocNode<ir::TSTypeParameterInstantiation>(std::move(params_vector));
        return params;
    }();

    auto *promise_void_type = [checker, void_param]() {
        auto *promise_id =
            checker->AllocNode<ir::Identifier>(compiler::Signatures::BUILTIN_PROMISE_CLASS, checker->Allocator());
        promise_id->SetReference();
        auto *part = checker->AllocNode<ir::ETSTypeReferencePart>(promise_id, void_param, nullptr);
        auto *type = checker->AllocNode<ir::ETSTypeReference>(part);
        return type;
    }();

    SetRangeRecursively(promise_void_type, loc);

    return promise_void_type;
}

static bool CheckForPromiseVoid(const ir::TypeNode *type)
{
    if (type == nullptr || !type->IsETSTypeReference()) {
        return false;
    }

    auto *type_ref = type->AsETSTypeReference();
    auto *type_part = type_ref->Part();
    if (type_part->Previous() != nullptr) {
        return false;
    }

    const auto &params = type_part->TypeParams()->Params();
    if (params.size() != 1) {
        return false;
    }

    const auto &param = params.at(0);
    if (!param->IsETSTypeReference()) {
        return false;
    }

    const auto *param_ref = param->AsETSTypeReference();
    const auto *param_part = param_ref->Part();
    if (param_part->Previous() != nullptr) {
        return false;
    }

    const auto is_type_promise =
        type_part->Name()->AsIdentifier()->Name() == compiler::Signatures::BUILTIN_PROMISE_CLASS;
    const auto is_param_void = param_part->Name()->AsIdentifier()->Name() == compiler::Signatures::BUILTIN_VOID_CLASS;

    return is_type_promise && is_param_void;
}

bool PromiseVoidLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    auto *checker = ctx->checker->AsETSChecker();

    auto gen_type_location = [](ir::ScriptFunction *function) -> lexer::SourceRange {
        const auto &params = function->Params();
        const auto &id = function->Id();
        const auto &body = function->Body();
        if (!params.empty()) {
            const auto &last = params.back();
            const auto &loc = last->Range();
            return {loc.end, loc.end};
        }

        if (id != nullptr) {
            const auto &loc = id->Range();
            return {loc.end, loc.end};
        }

        if (function->HasBody()) {
            const auto &loc = body->Range();
            return {loc.start, loc.start};
        }

        const auto &loc = function->Range();
        return {loc.end, loc.end};
    };

    program->Ast()->TransformChildrenRecursively([checker, gen_type_location](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsScriptFunction() && ast->AsScriptFunction()->IsAsyncFunc()) {
            auto *function = ast->AsScriptFunction();
            auto *return_ann = function->ReturnTypeAnnotation();
            const auto has_return_ann = return_ann != nullptr;
            const auto has_promise_void = CheckForPromiseVoid(return_ann);

            if (!has_return_ann) {
                const auto &loc = gen_type_location(function);
                function->SetReturnTypeAnnotation(CreatePromiseVoidType(checker, loc));

                if (function->HasBody()) {
                    HandleAsyncScriptFunctionBody(checker, function->Body()->AsBlockStatement());
                }
            } else if (has_promise_void && function->HasBody()) {
                HandleAsyncScriptFunctionBody(checker, function->Body()->AsBlockStatement());
            }
        }

        return ast;
    });

    return true;
}

bool PromiseVoidLowering::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    (void)ctx;

    auto check_function_body = [](const ir::BlockStatement *body) -> bool {
        if (body->IsReturnStatement()) {
            auto *return_stmt = body->AsReturnStatement();
            const auto *arg = return_stmt->Argument();

            if (!arg->IsIdentifier()) {
                return false;
            }

            const auto *id = arg->AsIdentifier();
            return id->Name() == compiler::Signatures::VOID_OBJECT;
        }

        return true;
    };

    auto is_ok = true;
    program->Ast()->IterateRecursively([check_function_body, &is_ok](ir::AstNode *ast) {
        if (ast->IsScriptFunction() && ast->AsScriptFunction()->IsAsyncFunc()) {
            auto *function = ast->AsScriptFunction();
            auto *return_ann = function->ReturnTypeAnnotation();
            if (!CheckForPromiseVoid(return_ann)) {
                return;
            }
            if (function->HasBody()) {
                if (!check_function_body(function->Body()->AsBlockStatement())) {
                    is_ok = false;
                    return;
                }
            }
        }
        return;
    });

    return is_ok;
}
}  // namespace panda::es2panda::compiler
