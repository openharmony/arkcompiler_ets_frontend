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

#include "checker/ETSchecker.h"
#include "checker/types/globalTypesHolder.h"
#include "evaluate/helpers.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/blockStatement.h"
#include "ir/ts/tsArrayType.h"
#include "ir/typeNode.h"

#include "assembler/assembly-type.h"
#include "libpandafile/field_data_accessor-inl.h"

#include <algorithm>
#include <unordered_map>

namespace ark::es2panda::evaluate {

static ir::TypeNode *PrimitiveToTypeNode(panda_file::Type::TypeId typeId, checker::ETSChecker *checker)
{
    static std::unordered_map<panda_file::Type::TypeId, ir::PrimitiveType> primitivesMap = {
        {panda_file::Type::TypeId::VOID, ir::PrimitiveType::VOID},
        {panda_file::Type::TypeId::U1, ir::PrimitiveType::BOOLEAN},
        {panda_file::Type::TypeId::I8, ir::PrimitiveType::CHAR},
        {panda_file::Type::TypeId::U8, ir::PrimitiveType::BYTE},
        {panda_file::Type::TypeId::I16, ir::PrimitiveType::SHORT},
        {panda_file::Type::TypeId::U16, ir::PrimitiveType::SHORT},
        {panda_file::Type::TypeId::I32, ir::PrimitiveType::INT},
        {panda_file::Type::TypeId::U32, ir::PrimitiveType::INT},
        {panda_file::Type::TypeId::F32, ir::PrimitiveType::FLOAT},
        {panda_file::Type::TypeId::F64, ir::PrimitiveType::DOUBLE},
        {panda_file::Type::TypeId::I64, ir::PrimitiveType::LONG},
        {panda_file::Type::TypeId::U64, ir::PrimitiveType::LONG},
    };

    auto it = primitivesMap.find(typeId);
    if (it != primitivesMap.end()) {
        return checker->AllocNode<ir::ETSPrimitiveType>(it->second);
    }
    UNREACHABLE();
    return nullptr;
}

static ir::TypeNode *ClassReferenceToTypeNode(std::string_view name, checker::ETSChecker *checker)
{
    util::UString typeName(name, checker->Allocator());
    auto *ident = checker->AllocNode<ir::Identifier>(typeName.View(), checker->Allocator());
    ident->SetReference();

    auto *typeRefPart = checker->AllocNode<ir::ETSTypeReferencePart>(ident, nullptr, nullptr);
    return checker->AllocNode<ir::ETSTypeReference>(typeRefPart);
}

static ir::TypeNode *ReferenceToTypeNode(std::string_view typeSignature, checker::ETSChecker *checker)
{
    ASSERT(checker);
    ASSERT(!typeSignature.empty());
    switch (typeSignature[0]) {
        case 'L': {
            // Variable is a reference.
            ASSERT(typeSignature.back() == ';');
            // Required to remove "std/core/" prefix, otherwise type name won't be parsed.
            auto startPos = typeSignature.find_last_of('/');
            if (startPos == std::string_view::npos) {
                startPos = 1;
            } else {
                startPos += 1;
            }
            return ClassReferenceToTypeNode(typeSignature.substr(startPos, typeSignature.size() - 1 - startPos),
                                            checker);
        }
        case '[': {
            // Variable is an array.
            size_t rank = std::count(typeSignature.begin(), typeSignature.end(), '[');
            auto *elementType = ToTypeNode(typeSignature.substr(rank), checker);
            if (elementType) {
                for (size_t i = 0; i < rank; ++i) {
                    elementType = checker->AllocNode<ir::TSArrayType>(elementType);
                }
                return elementType;
            }
            return nullptr;
        }
        default:
            return nullptr;
    }
    return nullptr;
}

ir::TypeNode *ToTypeNode(std::string_view typeSignature, checker::ETSChecker *checker)
{
    ASSERT(checker);
    ASSERT(!typeSignature.empty());

    if (typeSignature[0] == 'L' || typeSignature[0] == '[') {
        return ReferenceToTypeNode(typeSignature, checker);
    }

    pandasm::Type type = pandasm::Type::FromDescriptor(typeSignature);

    return PrimitiveToTypeNode(type.GetId(), checker);
}

ir::TypeNode *PandaTypeToTypeNode(const panda_file::File &pf, panda_file::FieldDataAccessor &fda,
                                  checker::ETSChecker *checker)
{
    auto pandaType = panda_file::Type::GetTypeFromFieldEncoding(fda.GetType());
    if (pandaType.IsReference()) {
        auto typeId = panda_file::FieldDataAccessor::GetTypeId(pf, fda.GetFieldId());
        std::string_view refSignature = utf::Mutf8AsCString(pf.GetStringData(typeId).data);
        return ReferenceToTypeNode(refSignature, checker);
    } else {
        return PrimitiveToTypeNode(pandaType.GetId(), checker);
    }
    return nullptr;
}

ir::TypeNode *PandaTypeToTypeNode(const panda_file::File &pf, panda_file::Type pandaType,
                                  panda_file::File::EntityId classId, checker::ETSChecker *checker)
{
    if (pandaType.IsReference()) {
        ASSERT(classId.IsValid());
        std::string_view refSignature = utf::Mutf8AsCString(pf.GetStringData(classId).data);
        return ReferenceToTypeNode(refSignature, checker);
    } else {
        return PrimitiveToTypeNode(pandaType.GetId(), checker);
    }
    return nullptr;
}

static checker::Type *PrimitiveToCheckerType(panda_file::Type::TypeId typeId, checker::GlobalTypesHolder *globalTypes)
{
    ASSERT(globalTypes);
    switch (typeId) {
        case panda_file::Type::TypeId::VOID:
            return globalTypes->GlobalETSVoidType();
        case panda_file::Type::TypeId::U1:
            return globalTypes->GlobalBooleanType();
        case panda_file::Type::TypeId::I8:
            return globalTypes->GlobalCharType();
        case panda_file::Type::TypeId::U8:
            return globalTypes->GlobalByteType();
        case panda_file::Type::TypeId::I16:
            [[fallthrough]];
        case panda_file::Type::TypeId::U16:
            return globalTypes->GlobalShortType();
        case panda_file::Type::TypeId::I32:
            [[fallthrough]];
        case panda_file::Type::TypeId::U32:
            return globalTypes->GlobalIntType();
        case panda_file::Type::TypeId::F32:
            return globalTypes->GlobalFloatType();
        case panda_file::Type::TypeId::F64:
            return globalTypes->GlobalDoubleType();
        case panda_file::Type::TypeId::I64:
            [[fallthrough]];
        case panda_file::Type::TypeId::U64:
            return globalTypes->GlobalLongType();
        default:
            return nullptr;
    }
    return nullptr;
}

static std::optional<std::string> ReferenceToName(std::string_view typeSignature,
                                                  checker::GlobalTypesHolder *globalTypes)
{
    ASSERT(globalTypes);
    ASSERT(!typeSignature.empty());
    switch (typeSignature[0]) {
        case 'L': {
            // Variable is a reference.
            ASSERT(typeSignature.back() == ';');
            // Required to remove "std/core/" prefix, otherwise type name won't be parsed.
            auto startPos = typeSignature.find_last_of('/');
            if (startPos == std::string_view::npos) {
                startPos = 1;
            } else {
                startPos += 1;
            }
            return std::string(typeSignature.substr(startPos, typeSignature.size() - 1 - startPos));
        }
        case '[': {
            // Variable is an array.
            auto rank = std::count(typeSignature.begin(), typeSignature.end(), '[');
            auto elementType = ToTypeName(typeSignature.substr(rank), globalTypes);
            if (!elementType) {
                return elementType;
            }

            auto &arrayType = *elementType;
            auto subtypeSize = arrayType.size();
            arrayType.resize(subtypeSize + rank * 2);
            for (size_t i = subtypeSize, end = arrayType.size(); i < end; i += 2) {
                arrayType[i] = '[';
                arrayType[i + 1] = ']';
            }
            return arrayType;
        }
        default:
            UNREACHABLE();
    }
    return {};
}

std::optional<std::string> ToTypeName(std::string_view typeSignature, checker::GlobalTypesHolder *globalTypes)
{
    ASSERT(globalTypes);
    ASSERT(!typeSignature.empty());

    if (typeSignature[0] == 'L' || typeSignature[0] == '[') {
        return ReferenceToName(typeSignature, globalTypes);
    }

    pandasm::Type type = pandasm::Type::FromDescriptor(typeSignature);

    auto *checkerType = PrimitiveToCheckerType(type.GetId(), globalTypes);
    ASSERT(checkerType);
    return checkerType->ToString();
}

panda_file::Type::TypeId GetTypeId(std::string_view typeSignature)
{
    if (typeSignature.empty()) {
        return panda_file::Type::TypeId::INVALID;
    }
    if (typeSignature[0] == 'L' || typeSignature[0] == '[') {
        return panda_file::Type::TypeId::REFERENCE;
    }
    pandasm::Type type = pandasm::Type::FromDescriptor(typeSignature);
    return type.GetId();
}

ir::BlockStatement *GetEnclosingBlock(ir::Identifier *ident)
{
    ASSERT(ident);

    ir::AstNode *iter = ident;

    while (iter->Parent() && !iter->IsBlockStatement()) {
        iter = iter->Parent();
    }

    ASSERT(iter);
    return iter->AsBlockStatement();
}

// TODO: make this method template for both fields and methods.
ir::ModifierFlags GetModifierFlags(panda_file::FieldDataAccessor &fda)
{
    auto flags = ir::ModifierFlags::NONE;
    if (fda.IsStatic()) {
        flags |= ir::ModifierFlags::STATIC;
    }
    if (fda.IsPublic()) {
        flags |= ir::ModifierFlags::PUBLIC;
    }
    if (fda.IsProtected()) {
        flags |= ir::ModifierFlags::PROTECTED;
    }
    if (fda.IsPrivate()) {
        flags |= ir::ModifierFlags::PRIVATE;
    }
    if (fda.IsFinal()) {
        flags |= ir::ModifierFlags::FINAL;
    }
    if (fda.IsReadonly()) {
        flags |= ir::ModifierFlags::READONLY;
    }
    return flags;
}

SafeStateScope::SafeStateScope(checker::ETSChecker *checker)
    : checker_(checker),
      checkerScope_(checker->Scope()),
      binderTopScope_(checker->VarBinder()->TopScope()),
      binderVarScope_(checker->VarBinder()->VarScope()),
      binderScope_(checker->VarBinder()->GetScope()),
      binderProgram_(checker->VarBinder()->AsETSBinder()->Program()),
      recordTable_(checker->VarBinder()->AsETSBinder()->GetRecordTable())
{
}

SafeStateScope::~SafeStateScope()
{
    ASSERT(checkerScope_ == checker_->Scope());
    ASSERT(binderTopScope_ == checker_->VarBinder()->TopScope());
    ASSERT(binderVarScope_ == checker_->VarBinder()->VarScope());
    ASSERT(binderScope_ == checker_->VarBinder()->GetScope());
    ASSERT(binderProgram_ == checker_->VarBinder()->AsETSBinder()->Program());
    ASSERT(recordTable_ == checker_->VarBinder()->AsETSBinder()->GetRecordTable());
}

void AddExternalProgram(parser::Program *program, parser::Program *extProgram, std::string_view moduleName)
{
    ASSERT(program);
    ASSERT(extProgram);

    auto &extSources = program->ExternalSources();
    if (extSources.count(moduleName) == 0) {
        extSources.emplace(moduleName, program->Allocator()->Adapter());
    }
    extSources.at(moduleName).emplace_back(extProgram);
}

}  // namespace ark::es2panda::evaluate
