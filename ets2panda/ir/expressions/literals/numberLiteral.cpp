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

#include "numberLiteral.h"

#include "util/helpers.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void NumberLiteral::TransformChildren([[maybe_unused]] const NodeTransformer &cb) {}
void NumberLiteral::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void NumberLiteral::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "NumberLiteral"}, {"value", number_}});
}

void NumberLiteral::Compile(compiler::PandaGen *pg) const
{
    if (std::isnan(number_.GetDouble())) {
        pg->LoadConst(this, compiler::Constant::JS_NAN);
    } else if (!std::isfinite(number_.GetDouble())) {
        pg->LoadConst(this, compiler::Constant::JS_INFINITY);
    } else if (util::Helpers::IsInteger<int32_t>(number_.GetDouble())) {
        pg->LoadAccumulatorInt(this, static_cast<int32_t>(number_.GetDouble()));
    } else {
        pg->LoadAccumulatorDouble(this, number_.GetDouble());
    }
}

void NumberLiteral::Compile(compiler::ETSGen *etsg) const
{
    auto ttctx = compiler::TargetTypeContext(etsg, TsType());
    if (number_.IsInt()) {
        if (util::Helpers::IsTargetFitInSourceRange<checker::ByteType::UType, checker::IntType::UType>(
                number_.GetInt())) {
            etsg->LoadAccumulatorByte(this, static_cast<int8_t>(number_.GetInt()));
            return;
        }

        if (util::Helpers::IsTargetFitInSourceRange<checker::ShortType::UType, checker::IntType::UType>(
                number_.GetInt())) {
            etsg->LoadAccumulatorShort(this, static_cast<int16_t>(number_.GetInt()));
            return;
        }

        etsg->LoadAccumulatorInt(this, static_cast<int32_t>(number_.GetInt()));
        return;
    }

    if (number_.IsLong()) {
        etsg->LoadAccumulatorWideInt(this, number_.GetLong());
        return;
    }

    if (number_.IsFloat()) {
        etsg->LoadAccumulatorFloat(this, number_.GetFloat());
        return;
    }

    etsg->LoadAccumulatorDouble(this, number_.GetDouble());
}

checker::Type *NumberLiteral::Check(checker::TSChecker *checker)
{
    auto search = checker->NumberLiteralMap().find(number_.GetDouble());
    if (search != checker->NumberLiteralMap().end()) {
        return search->second;
    }

    auto *new_num_literal_type = checker->Allocator()->New<checker::NumberLiteralType>(number_.GetDouble());
    checker->NumberLiteralMap().insert({number_.GetDouble(), new_num_literal_type});
    return new_num_literal_type;
}

checker::Type *NumberLiteral::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    if (number_.IsInt()) {
        SetTsType(checker->CreateIntType(number_.GetInt()));
        return TsType();
    }

    if (number_.IsLong()) {
        SetTsType(checker->CreateLongType(number_.GetLong()));
        return TsType();
    }

    if (number_.IsFloat()) {
        SetTsType(checker->CreateFloatType(number_.GetFloat()));
        return TsType();
    }

    SetTsType(checker->CreateDoubleType(number_.GetDouble()));
    return TsType();
}
}  // namespace panda::es2panda::ir
