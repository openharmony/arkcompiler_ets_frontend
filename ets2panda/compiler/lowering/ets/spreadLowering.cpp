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

#include "spreadLowering.h"
#include "checker/ETSchecker.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"
#include "ir/expressions/literals/numberLiteral.h"

namespace ark::es2panda::compiler {

using AstNodePtr = ir::AstNode *;

std::string SpreadConstructionPhase::CreateLengthString(ir::ArrayExpression *array)
{
    int spreadElementCount = 0;
    std::stringstream lengthCalculationString;

    for (const auto *element : array->Elements()) {
        if (element->Type() == ir::AstNodeType::SPREAD_ELEMENT) {
            spreadElementCount++;
            lengthCalculationString << element->AsSpreadElement()->Argument()->AsIdentifier()->Name() << ".length + ";
        }
    }

    lengthCalculationString << "0";
    int newArrayLength = array->Elements().size() - spreadElementCount;
    std::stringstream lengthString;
    lengthString << "let length : int = " << newArrayLength << " + " << lengthCalculationString.str();

    return lengthString.str();
}

std::string SpreadConstructionPhase::CreateETSCode(ir::ArrayExpression *array, std::vector<ir::AstNode *> &node,
                                                   public_lib::Context *ctx)
{
    std::stringstream src;
    std::string lengthString = CreateLengthString(array);
    std::string arrayType = array->TsType()->AsETSArrayType()->ElementType()->ToString();

    src.clear();
    std::string newArrayName = "tempArrayVar";
    src << lengthString << std::endl;
    src << "type typeOfTempArray = " << arrayType << std::endl;
    src << "let " << newArrayName << ": typeOfTempArray[] = new typeOfTempArray[length]" << std::endl;
    src << "let newArrayIndex = 0" << std::endl;
    size_t argumentCount = 1;

    for (std::uint32_t i = 0; i < array->Elements().size(); ++i) {
        if (array->Elements()[i]->Type() == ir::AstNodeType::SPREAD_ELEMENT) {
            std::string spreadArrayName =
                array->Elements()[i]->AsSpreadElement()->Argument()->AsIdentifier()->Name().Mutf8();
            src << "let elementOfSpread" << i << ": " << array->Elements()[i]->TsType()->ToString() << std::endl;
            src << "for (elementOfSpread" << i << " of " << spreadArrayName << ") {" << std::endl;
            src << newArrayName << "[newArrayIndex] = "
                << "elementOfSpread" << i << std::endl;
            src << "newArrayIndex++" << std::endl;
            src << "}" << std::endl;
        } else {
            src << newArrayName << "[newArrayIndex] = "
                << "(@@E" << argumentCount << ")" << std::endl;
            src << "newArrayIndex++" << std::endl;
            argumentCount++;
            node.emplace_back(array->Elements()[i]->Clone(ctx->allocator, nullptr));
        }
    }
    src << newArrayName << ";" << std::endl;
    std::cout << src.str() << std::endl;

    return src.str();
}

bool SpreadConstructionPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    auto *const parser = ctx->parser->AsETSParser();
    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        [&parser, &checker, &ctx, this](ir::AstNode *const node) -> AstNodePtr {
            if (node->IsArrayExpression() &&
                std::any_of(node->AsArrayExpression()->Elements().begin(), node->AsArrayExpression()->Elements().end(),
                            [](const auto *param) { return param->Type() == ir::AstNodeType::SPREAD_ELEMENT; })) {
                auto scopeCtx =
                    varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), NearestScope(node));
                std::vector<ir::AstNode *> normalElements {};
                std::string src = CreateETSCode(node->AsArrayExpression(), normalElements, ctx);

                ir::BlockExpression *blockExpression =
                    parser->CreateFormattedExpression(src, normalElements)->AsBlockExpression();
                blockExpression->SetParent(node->Parent());
                InitScopesPhaseETS::RunExternalNode(blockExpression, checker->VarBinder());
                checker->VarBinder()->AsETSBinder()->ResolveReferencesForScope(blockExpression,
                                                                               NearestScope(blockExpression));
                blockExpression->Check(checker);

                return blockExpression;
            }

            return node;
        },
        Name());
    return true;
}

bool SpreadConstructionPhase::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            if (!Postcondition(ctx, extProg)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace ark::es2panda::compiler
