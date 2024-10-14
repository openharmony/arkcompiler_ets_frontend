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

std::string SpreadConstructionPhase::CreateLengthString(ir::ArrayExpression *array,
                                                        const std::string_view spreadArrayName,
                                                        const std::string_view lengthOfNewArray)
{
    int spreadElementCount = 0;
    std::stringstream lengthCalculationString;

    for (std::size_t i = 0; i < array->Elements().size(); ++i) {
        if (array->Elements()[i]->Type() == ir::AstNodeType::SPREAD_ELEMENT) {
            spreadElementCount++;
            lengthCalculationString << spreadArrayName << "_" << i << ".length + ";
        }
    }

    lengthCalculationString << "0";
    int newArrayLength = array->Elements().size() - spreadElementCount;
    std::stringstream lengthString;
    lengthString << "let " << lengthOfNewArray << " : int = " << newArrayLength << " + "
                 << lengthCalculationString.str() << std::endl;

    return lengthString.str();
}

/*
 * NOTE: Create sourceCode to expand the SpreadExpression, which is as follows :
 * let spreadArrayName_0 = (@@E1)
 * let length : int = 0 + spreadArrayName_0.length + 0
 * type typeOfNewArray = arrayType
 * let tempArrayVar: typeOfNewArray[] = new typeOfNewArray[length]
 * let newArrayIndex = 0
 * let elementOfSpread_0: arrayType
 * for (elementOfSpread_0 of spreadArrayName_0) {
 *     tempArrayVar[newArrayIndex] = elementOfSpread_0
 *     newArrayIndex++
 * }
 * tempArrayVar[newArrayIndex] = (@@E2)
 * newArrayIndex++
 * ...
 * tempArrayVar;
 */
std::string SpreadConstructionPhase::CreateETSCode(ir::ArrayExpression *array, std::vector<ir::AstNode *> &node,
                                                   public_lib::Context *ctx)
{
    const util::StringView &spreadArrayName = GenName(ctx->checker->Allocator()).View();
    const util::StringView &newArrayName = GenName(ctx->checker->Allocator()).View();
    const util::StringView &newArrayIndex = GenName(ctx->checker->Allocator()).View();
    const util::StringView &typeOfNewArray = GenName(ctx->checker->Allocator()).View();
    const util::StringView &elementOfSpread = GenName(ctx->checker->Allocator()).View();
    const util::StringView &lengthOfNewArray = GenName(ctx->checker->Allocator()).View();

    std::string lengthString = CreateLengthString(array, spreadArrayName.Utf8(), lengthOfNewArray.Utf8());
    std::string arrayType = array->TsType()->AsETSArrayType()->ElementType()->ToString();

    std::stringstream src;
    src.clear();
    size_t argumentCount = 1;

    for (std::size_t i = 0; i < array->Elements().size(); ++i) {
        if (array->Elements()[i]->Type() != ir::AstNodeType::SPREAD_ELEMENT) {
            continue;
        }
        src << "let " << spreadArrayName << "_" << i << " = (@@E" << argumentCount << ")" << std::endl;
        argumentCount++;
        node.emplace_back(array->Elements()[i]->AsSpreadElement()->Argument()->Clone(ctx->allocator, nullptr));
    }

    src << lengthString << std::endl;

    // NOTE: For ETSUnionType(String|Int) or ETSObjectType(private constructor) or ..., we canot use "new Type[]" to
    //       declare an array, so we add "|null" to solve it temporarily.
    //       We might need to use cast Expression in the end of the generated source code to remove "|null", such as
    //       "newArrayName as arrayType[]".
    //       But now cast Expression doesn't support built-in array (cast fatherType[] to sonType[]), so "newArrayName
    //       as arrayType" should be added after cast Expression is implemented completely.
    src << "type " << typeOfNewArray << " = " << arrayType << "|null" << std::endl;
    src << "let " << newArrayName << ": " << typeOfNewArray << "[] = "
        << "new " << typeOfNewArray << "[" << lengthOfNewArray << "]" << std::endl;
    src << "let " << newArrayIndex << " = 0" << std::endl;

    for (std::size_t i = 0; i < array->Elements().size(); ++i) {
        if (array->Elements()[i]->Type() == ir::AstNodeType::SPREAD_ELEMENT) {
            src << "let " << elementOfSpread << "_" << i << ": " << arrayType << std::endl;
            src << "for (" << elementOfSpread << "_" << i << " of " << spreadArrayName << "_" << i << ") {"
                << std::endl;
            src << newArrayName << "[" << newArrayIndex << "] = " << elementOfSpread << "_" << i << std::endl;
            src << newArrayIndex << "++" << std::endl;
            src << "}" << std::endl;
        } else {
            src << newArrayName << "[" << newArrayIndex << "] = (@@E" << argumentCount << ")" << std::endl;
            src << newArrayIndex << "++" << std::endl;
            argumentCount++;
            node.emplace_back(array->Elements()[i]->Clone(ctx->allocator, nullptr));
        }
    }
    src << newArrayName << ";" << std::endl;

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
