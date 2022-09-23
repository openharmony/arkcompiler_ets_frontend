/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hotfix.h"
#include <binder/binder.h>
#include <binder/scope.h>
#include <binder/variable.h>
#include <compiler/core/pandagen.h>
#include <ir/expressions/literal.h>

#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

namespace panda::es2panda::util {

constexpr std::string_view ANONYMOUS_OR_DUPLICATE_FUNCTION_SPECIFIER = "#";
const std::string EXTERNAL_ATTRIBUTE = "external";
const uint32_t PATCH_ENV_VREG = 0;  // reuse first param vreg
const panda::panda_file::SourceLang SRC_LANG = panda::panda_file::SourceLang::ECMASCRIPT;

void Hotfix::ProcessFunction(const compiler::PandaGen *pg, panda::pandasm::Function *func,
    LiteralBuffers &literalBuffers)
{
    if (generateSymbolFile_) {
        DumpFunctionInfo(pg, func, literalBuffers);
        return;
    }

    if (generatePatch_) {
        HandleFunction(pg, func, literalBuffers);
        return;
    }
}

void Hotfix::ProcessModule(const std::string &recordName,
    std::vector<panda::pandasm::LiteralArray::Literal> &moduleBuffer)
{
    if (generateSymbolFile_) {
        DumpModuleInfo(recordName, moduleBuffer);
        return;
    }

    if (generatePatch_) {
        ValidateModuleInfo(recordName, moduleBuffer);
        return;
    }
}

void Hotfix::DumpModuleInfo(const std::string &recordName,
    std::vector<panda::pandasm::LiteralArray::Literal> &moduleBuffer)
{
    std::stringstream ss;
    ss << recordName << SymbolTable::SECOND_LEVEL_SEPERATOR;
    auto hash = std::hash<std::string>{}(ConvertLiteralToString(moduleBuffer));
    ss << hash << std::endl;
    symbolTable_->WriteSymbolTable(ss.str());
}

void Hotfix::ValidateModuleInfo(const std::string &recordName,
    std::vector<panda::pandasm::LiteralArray::Literal> &moduleBuffer)
{
    auto it = originModuleInfo_->find(recordName);
    if (it == originModuleInfo_->end()) {
        std::cerr << "Found new import/export expression in " << recordName << ", not supported!" << std::endl;
        patchError_ = true;
        return;
    }

    auto hash = std::hash<std::string>{}(ConvertLiteralToString(moduleBuffer));
    if (std::to_string(hash) != it->second) {
        std::cerr << "Found import/export expression changed in " << recordName << ", not supported!" << std::endl;
        patchError_ = true;
        return;
    }
}

bool Hotfix::IsAnonymousOrDuplicateNameFunction(const std::string &funcName)
{
    return funcName.find(ANONYMOUS_OR_DUPLICATE_FUNCTION_SPECIFIER) != std::string::npos;
}

std::vector<std::pair<std::string, size_t>> Hotfix::GenerateFunctionAndClassHash(panda::pandasm::Function *func,
    LiteralBuffers &literalBuffers)
{
    std::stringstream ss;
    std::vector<std::pair<std::string, size_t>> hashList;

    ss << ".function any " << func->name << '(';

    for (uint32_t i = 0; i < func->GetParamsNum(); i++) {
        ss << "any a" << std::to_string(i);
        if (i != func->GetParamsNum() - 1) {
            ss << ", ";
        }
    }
    ss << ") {" << std::endl;

    for (const auto &ins : func->ins) {
        ss << (ins.set_label ? "" : "\t") << ins.ToString("", true, func->GetTotalRegs()) << " ";
        if (ins.opcode == panda::pandasm::Opcode::ECMA_CREATEARRAYWITHBUFFER ||
            ins.opcode == panda::pandasm::Opcode::ECMA_CREATEOBJECTWITHBUFFER) {
            int64_t bufferIdx = std::get<int64_t>(ins.imms[0]);
            ss << ExpandLiteral(bufferIdx, literalBuffers) << " ";
        } else if (ins.opcode == panda::pandasm::Opcode::ECMA_DEFINECLASSWITHBUFFER) {
            int64_t bufferIdx = std::get<int64_t>(ins.imms[0]);
            std::string literalStr = ExpandLiteral(bufferIdx, literalBuffers);
            auto classHash = std::hash<std::string>{}(literalStr);
            hashList.push_back(std::pair<std::string, size_t>(ins.ids[0], classHash));
            CollectClassMemberFunctions(ins.ids[0], bufferIdx, literalBuffers);
        }
        ss << " ";
    }

    ss << "}" << std::endl;

    for (const auto &ct : func->catch_blocks) {
        ss << ".catchall " << ct.try_begin_label << ", " << ct.try_end_label << ", " << ct.catch_begin_label
            << std::endl;
    }

    auto funcHash = std::hash<std::string>{}(ss.str());
    hashList.push_back(std::pair<std::string, size_t>(func->name, funcHash));
    return hashList;
}

std::string Hotfix::ConvertLiteralToString(std::vector<panda::pandasm::LiteralArray::Literal> &literalBuffer)
{
    std::stringstream ss;
    int count = 0;
    for (auto &literal : literalBuffer) {
        ss << "{" << "index: " << count++ << " ";
        ss << "tag: " << static_cast<std::underlying_type<panda::es2panda::ir::LiteralTag>::type>(literal.tag_);
        ss << " ";
        std::string val;
        std::visit([&val](auto&& element) {
            val += "val: ";
            val += element;
            val += " ";
        }, literal.value_ );
        ss << val;
        ss << "},";

    }

    return ss.str();
}

std::string Hotfix::ExpandLiteral(int64_t bufferIdx, Hotfix::LiteralBuffers &literalBuffers)
{
    for (auto &litPair : literalBuffers) {
        if (litPair.first == bufferIdx) {
            return ConvertLiteralToString(litPair.second);
        }
    }

    return "";
}

std::vector<std::string> Hotfix::GetLiteralMethods(int64_t bufferIdx, Hotfix::LiteralBuffers &literalBuffers)
{
    std::vector<std::string> methods;
    for (auto &litPair : literalBuffers) {
        if (litPair.first != bufferIdx) {
            continue;
        }
        for (auto &literal : litPair.second) {
            switch (literal.tag_) {
                case panda::panda_file::LiteralTag::METHOD:
                case panda::panda_file::LiteralTag::GENERATORMETHOD:
                case panda::panda_file::LiteralTag::ASYNCGENERATORMETHOD: {
                    methods.push_back(std::get<std::string>(literal.value_));
                    break;
                }
                default:
                    break;
            }
        }
    }

    return methods;
}

void Hotfix::CollectClassMemberFunctions(const std::string &className, int64_t bufferIdx,
    Hotfix::LiteralBuffers &literalBuffers)
{
    std::vector<std::string> classMemberFunctions = GetLiteralMethods(bufferIdx, literalBuffers);
    classMemberFunctions.push_back(className);
    classMemberFunctions_.insert({className, classMemberFunctions});
}

bool Hotfix::IsScopeValidToPatchLexical(binder::VariableScope *scope)
{
    if (!generatePatch_) {
        return false;
    }

    if (!scope->IsFunctionVariableScope()) {
        return false;
    }

    auto funcName = scope->AsFunctionVariableScope()->InternalName();
    if (std::string(funcName) != funcMain0_) {
        return false;
    }
    return true;
}

void Hotfix::AllocSlotfromPatchEnv(const std::string &variableName)
{
    if (!topScopeLexEnvs_.count(variableName)) {
        topScopeLexEnvs_[variableName] = topScopeIdx_++;
    }
}

uint32_t Hotfix::GetSlotIdFromSymbolTable(const std::string &variableName)
{
    auto functionIter = originFunctionInfo_->find(funcMain0_);
    if (functionIter != originFunctionInfo_->end()) {
        auto lexenvIter = functionIter->second.lexenv.find(variableName);
        if (lexenvIter != functionIter->second.lexenv.end()) {
            return lexenvIter->second.first;
        }
    }
    return UINT32_MAX;
}

uint32_t Hotfix::GetPatchLexicalIdx(const std::string &variableName)
{
    ASSERT(topScopeLexEnvs_.count(variableName));
    return topScopeLexEnvs_[variableName];
}

bool IsFunctionOrClassDefineIns(panda::pandasm::Ins &ins)
{
    if (ins.opcode == panda::pandasm::Opcode::ECMA_DEFINEGENERATORFUNC ||
        ins.opcode == panda::pandasm::Opcode::ECMA_DEFINEMETHOD ||
        ins.opcode == panda::pandasm::Opcode::ECMA_DEFINEFUNCDYN ||
        ins.opcode == panda::pandasm::Opcode::ECMA_DEFINEASYNCFUNC ||
        ins.opcode == panda::pandasm::Opcode::ECMA_DEFINECLASSWITHBUFFER) {
        return true;
    }
    return false;
}

void Hotfix::CollectFuncDefineIns(panda::pandasm::Function *func)
{
    for (size_t i = 0; i < func->ins.size(); ++i) {
        if (IsFunctionOrClassDefineIns(func->ins[i])) {
            funcDefineIns_.push_back(func->ins[i]);  // push define ins
            funcDefineIns_.push_back(func->ins[i + 1]);  // push store ins
        }
    }
}

void Hotfix::HandleModifiedClasses(panda::pandasm::Program *prog)
{
    for (auto &cls: classMemberFunctions_) {
        for (auto &func: cls.second) {
            if (!prog->function_table.at(func).metadata->IsForeign()) {
                if (func == cls.first) {
                    std::cerr << "Found class: " << cls.first << " constructor modified, not supported!" << std::endl;
                    patchError_ = true;
                    return;
                }
                modifiedClassNames_.insert(cls.first);
                break;
            }
        }
    }

    for (auto &cls: modifiedClassNames_) {
        auto &memberFunctions = classMemberFunctions_[cls];
        for (auto &func: memberFunctions) {
            if (prog->function_table.at(func).metadata->IsForeign()) {
                prog->function_table.at(func).metadata->RemoveAttribute(EXTERNAL_ATTRIBUTE);
            }
        }
    }
}

void Hotfix::AddHeadAndTailInsForPatchFuncMain0(std::vector<panda::pandasm::Ins> &ins)
{
    panda::pandasm::Ins returnUndefine;
    returnUndefine.opcode = pandasm::Opcode::ECMA_RETURNUNDEFINED;

    if (ins.size() == 0) {
        ins.push_back(returnUndefine);
        return;
    }

    panda::pandasm::Ins newLexenv;
    newLexenv.opcode = pandasm::Opcode::ECMA_NEWLEXENVDYN;
    newLexenv.imms.reserve(1);
    auto newFuncNum = long(ins.size() / 2);  // each new function has 2 ins: define and store
    newLexenv.imms.emplace_back(newFuncNum);

    panda::pandasm::Ins stLexenv;
    stLexenv.opcode = pandasm::Opcode::STA_DYN;
    stLexenv.regs.reserve(1);
    stLexenv.regs.emplace_back(PATCH_ENV_VREG);

    ins.insert(ins.begin(), stLexenv);
    ins.insert(ins.begin(), newLexenv);
    ins.push_back(returnUndefine);
}

void Hotfix::CreateFunctionPatchMain0AndMain1(panda::pandasm::Function &patchFuncMain0,
    panda::pandasm::Function &patchFuncMain1)
{
    const size_t defaultParamCount = 3;
    patchFuncMain0.params.reserve(defaultParamCount);
    patchFuncMain1.params.reserve(defaultParamCount);
    for (uint32_t i = 0; i < defaultParamCount; ++i) {
        patchFuncMain0.params.emplace_back(panda::pandasm::Type("any", 0), SRC_LANG);
        patchFuncMain1.params.emplace_back(panda::pandasm::Type("any", 0), SRC_LANG);
    }

    std::vector<panda::pandasm::Ins> patchMain0DefineIns;
    std::vector<panda::pandasm::Ins> patchMain1DefineIns;

    for (size_t i = 0; i < funcDefineIns_.size(); ++i) {
        if (IsFunctionOrClassDefineIns(funcDefineIns_[i])) {
            auto &name = funcDefineIns_[i].ids[0];
            if (newFuncNames_.count(name)) {
                funcDefineIns_[i].regs[0] = PATCH_ENV_VREG;
                patchMain0DefineIns.push_back(funcDefineIns_[i]);
                patchMain0DefineIns.push_back(funcDefineIns_[i + 1]);
                continue;
            }
            if (patchFuncNames_.count(name) || modifiedClassNames_.count(name)) {
                patchMain1DefineIns.push_back(funcDefineIns_[i]);
                continue;
            }
        }
    }

    AddHeadAndTailInsForPatchFuncMain0(patchMain0DefineIns);

    patchFuncMain0.ins = patchMain0DefineIns;
    patchFuncMain1.ins = patchMain1DefineIns;
}

void Hotfix::Finalize(panda::pandasm::Program **prog)
{
    if (!generatePatch_) {
        return;
    }

    HandleModifiedClasses(*prog);

    if (patchError_) {
        *prog = nullptr;
        std::cerr << "Found unsupported change in file, will not generate patch!" << std::endl;
        return;
    }

    panda::pandasm::Function patchFuncMain0(patchMain0_, SRC_LANG);
    panda::pandasm::Function patchFuncMain1(patchMain1_, SRC_LANG);
    CreateFunctionPatchMain0AndMain1(patchFuncMain0, patchFuncMain1);

    (*prog)->function_table.emplace(patchFuncMain0.name, std::move(patchFuncMain0));
    (*prog)->function_table.emplace(patchFuncMain1.name, std::move(patchFuncMain1));
}

bool Hotfix::CompareLexenv(const std::string &funcName, const compiler::PandaGen *pg,
    SymbolTable::OriginFunctionInfo &bytecodeInfo)
{
    auto &lexicalVarNameAndTypes = pg->TopScope()->GetLexicalVarNameAndTypes();
    auto &lexenv = bytecodeInfo.lexenv;
    if (funcName != funcMain0_) {
        if (lexenv.size() != lexicalVarNameAndTypes.size()) {
            std::cerr << "Found lexenv size changed, not supported!" << std::endl;
            patchError_ = true;
            return false;
        }
        for (auto &variable: lexicalVarNameAndTypes) {
            auto varName = std::string(variable.second.first);
            auto lexenvIter = lexenv.find(varName);
            if (lexenvIter == lexenv.end()) {
                std::cerr << "Found new lex env added, not supported!" << std::endl;
                patchError_ = true;
                return false;
            }

            auto &lexInfo = lexenvIter->second;
            if (variable.first != lexInfo.first || variable.second.second != lexInfo.second) {
                std::cerr << "Found new lex env changed(slot or type), not supported!" << std::endl;
                patchError_ = true;
                return false;
            }
        }
    }
    return true;
}

bool Hotfix::CompareClassHash(std::vector<std::pair<std::string, size_t>> &hashList,
    SymbolTable::OriginFunctionInfo &bytecodeInfo)
{
    auto &classInfo = bytecodeInfo.classHash;
    for (size_t i = 0; i < hashList.size() - 1; ++i) {
        auto &className = hashList[i].first;
        auto classIter = classInfo.find(className);
        if (classIter != classInfo.end()) {
            if (classIter->second != std::to_string(hashList[i].second)) {
                std::cerr << "Found class " << hashList[i].first << " changed, not supported!" << std::endl;
                patchError_ = true;
                return false;
            }
        }
    }
    return true;
}

void Hotfix::HandleFunction(const compiler::PandaGen *pg, panda::pandasm::Function *func,
    LiteralBuffers &literalBuffers)
{
    std::string funcName = func->name;
    auto originFunction = originFunctionInfo_->find(funcName);
    if (originFunction == originFunctionInfo_->end()) {
        if (IsAnonymousOrDuplicateNameFunction(funcName)) {
            std::cerr << "Found new anonymous or duplicate name function " << funcName
                      << " not supported!" << std::endl;
            patchError_ = true;
            return;
        }
        newFuncNames_.insert(funcName);
        CollectFuncDefineIns(func);
        return;
    }

    auto &bytecodeInfo = originFunction->second;
    if (!CompareLexenv(funcName, pg, bytecodeInfo)) {
        return;
    }

    auto hashList = GenerateFunctionAndClassHash(func, literalBuffers);
    if (!CompareClassHash(hashList, bytecodeInfo)) {
        return;
    }

    auto funcHash = std::to_string(hashList.back().second);
    if (funcHash == bytecodeInfo.funcHash || funcName == funcMain0_) {
        func->metadata->SetAttribute(EXTERNAL_ATTRIBUTE);
    } else {
        patchFuncNames_.insert(funcName);
    }

    CollectFuncDefineIns(func);
}

void Hotfix::DumpFunctionInfo(const compiler::PandaGen *pg, panda::pandasm::Function *func,
    Hotfix::LiteralBuffers &literalBuffers)
{
    std::stringstream ss;

    ss << pg->InternalName();
    ss << SymbolTable::SECOND_LEVEL_SEPERATOR << pg->InternalName() << SymbolTable::SECOND_LEVEL_SEPERATOR;

    std::vector<std::pair<std::string, size_t>> hashList = GenerateFunctionAndClassHash(func, literalBuffers);
    ss << hashList.back().second << SymbolTable::SECOND_LEVEL_SEPERATOR;

    ss << SymbolTable::FIRST_LEVEL_SEPERATOR;
    for (size_t i = 0; i < hashList.size() - 1; ++i) {
        ss << hashList[i].first << SymbolTable::SECOND_LEVEL_SEPERATOR << hashList[i].second <<
            SymbolTable::SECOND_LEVEL_SEPERATOR;
    }
    ss << SymbolTable::SECOND_LEVEL_SEPERATOR << SymbolTable::FIRST_LEVEL_SEPERATOR;

    for (auto &variable: pg->TopScope()->GetLexicalVarNameAndTypes()) {
        ss << variable.second.first << SymbolTable::SECOND_LEVEL_SEPERATOR
           << variable.first << SymbolTable::SECOND_LEVEL_SEPERATOR
           << variable.second.second << SymbolTable::SECOND_LEVEL_SEPERATOR;
    }
    ss << SymbolTable::SECOND_LEVEL_SEPERATOR << std::endl;

    symbolTable_->WriteSymbolTable(ss.str());
}

bool Hotfix::IsPatchVar(uint32_t slot)
{
    return slot == UINT32_MAX;
}

} // namespace panda::es2panda::util
