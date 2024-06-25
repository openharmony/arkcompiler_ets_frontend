/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "recordLowering.h"
#include <algorithm>
#include <sstream>
#include <string_view>

#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "macros.h"

#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "utils/arena_containers.h"
#include "varbinder/ETSBinder.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::compiler {

std::string_view RecordLowering::Name() const
{
    static std::string const NAME = "RecordLowering";
    return NAME;
}

std::string RecordLowering::TypeToString(checker::Type *type) const
{
    std::stringstream ss;
    type->ToString(ss);
    return ss.str();
}

bool RecordLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            Perform(ctx, extProg);
        }
    }

    // Replace Record Object Expressions with Block Expressions
    program->Ast()->TransformChildrenRecursively(
        [this, ctx](ir::AstNode *ast) -> ir::AstNode * {
            if (ast->IsObjectExpression()) {
                return UpdateObjectExpression(ast->AsObjectExpression(), ctx);
            }

            return ast;
        },
        Name());

    return true;
}

void RecordLowering::CheckDuplicateKey(ir::ObjectExpression *expr, public_lib::Context *ctx)
{
    std::unordered_set<std::variant<int32_t, int64_t, float, double, util::StringView>> keySet;
    for (auto *it : expr->Properties()) {
        auto *prop = it->AsProperty();
        switch (prop->Key()->Type()) {
            case ir::AstNodeType::NUMBER_LITERAL: {
                auto number = prop->Key()->AsNumberLiteral()->Number();
                if ((number.IsInt() && keySet.insert(number.GetInt()).second) ||
                    (number.IsLong() && keySet.insert(number.GetLong()).second) ||
                    (number.IsFloat() && keySet.insert(number.GetFloat()).second) ||
                    (number.IsDouble() && keySet.insert(number.GetDouble()).second)) {
                    continue;
                }
                ctx->checker->AsETSChecker()->ThrowTypeError(
                    "An object literal cannot multiple properties with same name", expr->Start());
            }
            case ir::AstNodeType::STRING_LITERAL: {
                if (keySet.insert(prop->Key()->AsStringLiteral()->Str()).second) {
                    continue;
                }
                ctx->checker->AsETSChecker()->ThrowTypeError(
                    "An object literal cannot multiple properties with same name", expr->Start());
            }
            case ir::AstNodeType::IDENTIFIER: {
                ctx->checker->AsETSChecker()->ThrowTypeError("Object literal may only specify known properties",
                                                             expr->Start());
            }
            default: {
                UNREACHABLE();
                break;
            }
        }
    }
}

ir::Statement *RecordLowering::CreateStatement(const std::string &src, ir::Expression *ident, ir::Expression *key,
                                               ir::Expression *value, public_lib::Context *ctx)
{
    std::vector<ir::AstNode *> nodes;
    if (ident != nullptr) {
        nodes.push_back(ident);
    }

    if (key != nullptr) {
        nodes.push_back(key);
    }

    if (value != nullptr) {
        nodes.push_back(value);
    }

    auto parser = ctx->parser->AsETSParser();
    auto statements = parser->CreateFormattedStatements(src, nodes);
    if (!statements.empty()) {
        return *statements.begin();
    }

    return nullptr;
}

ir::Expression *RecordLowering::UpdateObjectExpression(ir::ObjectExpression *expr, public_lib::Context *ctx)
{
    auto checker = ctx->checker->AsETSChecker();
    if (expr->TsType() == nullptr) {
        // Hasn't been through checker
        checker->ThrowTypeError("Unexpected type error in Record object literal", expr->Start());
    }

    if (!expr->PreferredType()->IsETSObjectType()) {
        // Unexpected preferred type
        return expr;
    }

    std::stringstream ss;
    expr->TsType()->ToAssemblerType(ss);
    if (!(ss.str() == "escompat.Record" || ss.str() == "escompat.Map")) {
        // Only update object expressions for Map/Record types
        return expr;
    }

    // Access type arguments
    [[maybe_unused]] size_t constexpr NUM_ARGUMENTS = 2;
    auto typeArguments = expr->PreferredType()->AsETSObjectType()->TypeArguments();
    ASSERT(typeArguments.size() == NUM_ARGUMENTS);

    // check Duplicate key
    CheckDuplicateKey(expr, ctx);

    auto *const scope = NearestScope(expr);
    checker::SavedCheckerContext scc {checker, checker::CheckerStatus::IGNORE_VISIBILITY};
    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);

    // Create Block Expression
    auto block = CreateBlockExpression(expr, typeArguments[0], typeArguments[1], ctx);
    block->SetParent(expr->Parent());

    // Run checks
    InitScopesPhaseETS::RunExternalNode(block, ctx->checker->VarBinder());
    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScope(block, NearestScope(block));
    block->Check(checker);

    // Replace Object Expression with Block Expression
    return block;
}

ir::Expression *RecordLowering::CreateBlockExpression(ir::ObjectExpression *expr, checker::Type *keyType,
                                                      checker::Type *valueType, public_lib::Context *ctx)
{
    /* This function will create block expression in the following format
     *
     * let map = new Map<key_type, value_type>();
     * map.set(k1, v1)
     * map.set(k2, v2)
     * ...
     * map
     */
    auto checker = ctx->checker->AsETSChecker();

    // Initialize map with provided type arguments
    auto *ident = Gensym(checker->Allocator());
    std::stringstream ss;
    expr->TsType()->ToAssemblerType(ss);

    ArenaVector<ir::Statement *> statements(ctx->allocator->Adapter());
    auto &properties = expr->Properties();
    // currently we only have Map and Record in this if branch
    std::string containerType;
    if (ss.str() == "escompat.Map") {
        containerType = "Map";
    } else {
        containerType = "Record";
    }

    const std::string createSrc =
        "let @@I1 = new " + containerType + "<" + TypeToString(keyType) + "," + TypeToString(valueType) + ">()";
    statements.push_back(CreateStatement(createSrc, ident, nullptr, nullptr, ctx));

    // Build statements from properties

    for (const auto &property : properties) {
        ASSERT(property->IsProperty());
        auto p = property->AsProperty();
        statements.push_back(
            CreateStatement("@@I1.set(@@E2, @@E3)", ident->Clone(ctx->allocator, nullptr), p->Key(), p->Value(), ctx));
    }
    statements.push_back(CreateStatement("@@I1", ident->Clone(ctx->allocator, nullptr), nullptr, nullptr, ctx));

    // Create Block Expression
    auto block = checker->AllocNode<ir::BlockExpression>(std::move(statements));
    return block;
}

}  // namespace ark::es2panda::compiler
