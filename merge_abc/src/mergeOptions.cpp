/**
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

#include "mergeOptions.h"

#include <sstream>

namespace panda::proto {
// Options
Options::Options() : argparser_(new panda::PandArgParser()) {}

Options::~Options()
{
    delete argparser_;
}

bool Options::Parse(int argc, const char **argv) {
    panda::PandArg<bool> opHelp("help", false, "Print this message and exit");

    panda::PandArg<std::string> protoBinPath("protoBinPath", "", "path of proto bin files");
    panda::PandArg<std::string> protoBinSuffix("protoBinSuffix", "", "suffix of proto bin file");
    panda::PandArg<std::string> outputPandaFile("outputPandaFile", "", "name of merged panda file");

    argparser_->Add(&opHelp);
    argparser_->Add(&protoBinPath);
    argparser_->Add(&protoBinSuffix);
    argparser_->Add(&outputPandaFile);

    if (!argparser_->Parse(argc, argv) || opHelp.GetValue() || protoBinPath.GetValue().empty()) {
        std::stringstream ss;

        ss << argparser_->GetErrorString() << std::endl;
        ss << "Usage: "
           << "merge_abc"
           << " [OPTIONS]" << std::endl;
        ss << std::endl;
        ss << "optional arguments:" << std::endl;
        ss << argparser_->GetHelpString() << std::endl;

        errorMsg_ = ss.str();
        return false;
    }

    protoBinPath_ = protoBinPath.GetValue();
    if (!protoBinSuffix.GetValue().empty()) {
        protoBinSuffix_ = protoBinSuffix.GetValue();
    }
    if (!outputPandaFile.GetValue().empty()) {
        outputPandaFile_ = outputPandaFile.GetValue();
    }

    return true;
}
}
