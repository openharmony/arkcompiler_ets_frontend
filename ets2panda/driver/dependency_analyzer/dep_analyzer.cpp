/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dep_analyzer.h"

void DepAnalyzer::Dump(std::string &outFilePath)
{
    std::ofstream outFile(outFilePath);
    if (!outFile) {
        std::cerr << "Error when opening a file " << outFilePath << std::endl;
        return;
    }

    for (auto const &sp : sourcePaths_) {
        outFile << sp << std::endl;
    }

    outFile.close();
}

void DepAnalyzer::Dump(std::ostream &ostr)
{
    for (auto const &sp : sourcePaths_) {
        ostr << sp << std::endl;
    }
}

void DepAnalyzer::AddImports(ark::es2panda::parser::ETSParser *parser)
{
    ark::es2panda::util::StringView firstSourceFilePath = parser->GetGlobalProgramAbsName();
    sourcePaths_.emplace_back(std::string(firstSourceFilePath));

    ark::es2panda::util::ImportPathManager *manager = parser->GetImportPathManager();
    auto &parseList = manager->ParseList();

    for (auto &pl : parseList) {
        sourcePaths_.emplace_back(std::string(pl.importData.resolvedSource));
    }
}

int DepAnalyzer::AnalyzeDeps(int argc, const char **argv)
{
    int minArgCount = 2;
    if (argc < minArgCount) {
        std::cout << "No file has been entered for analysis" << std::endl;
        return 1;
    }

    const auto *impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
    auto *cfg = impl->CreateConfig(argc, argv);
    if (cfg == nullptr) {
        return 1;
    }
    auto *cfgImpl = reinterpret_cast<ark::es2panda::public_lib::ConfigImpl *>(cfg);
    auto parserInputCStr = cfgImpl->options->CStrParserInputContents().first;

    es2panda_Context *ctx =
        impl->CreateContextFromString(cfg, parserInputCStr, cfgImpl->options->SourceFileName().c_str());
    auto *ctxImpl = reinterpret_cast<ark::es2panda::public_lib::Context *>(ctx);
    ctxImpl->parser->SetParserStatus(ark::es2panda::parser::ParserStatus::DEPENDENCY_ANALYZER_MODE);
    impl->ProceedToState(ctx, ES2PANDA_STATE_PARSED);

    if (ctxImpl->state == ES2PANDA_STATE_ERROR) {
        std::cout << ctxImpl->errorMessage << std::endl;
        return 1;
    }

    auto *parser = reinterpret_cast<ark::es2panda::parser::ETSParser *>(ctxImpl->parser);
    AddImports(parser);

    impl->DestroyContext(ctx);
    impl->DestroyConfig(cfg);
    return 0;
}