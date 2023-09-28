/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

package com.ohos.migrator.staticTS.parser;

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.TerminalNode;

import java.util.LinkedList;
import java.util.List;

public class StaticTSContextBase extends ParserRuleContext {
    private List<TerminalNode> leadingComments;
    private List<TerminalNode> trailingComments;

    // The fields used by the API mapper:
    public String javaImport = null;
    public String javaType = null;
    public String javaTypeArgs = null;
    public String javaName = null;
    public String javaMethodArgs = null;
    public String javaMethodTypeArgs = null;

    public StaticTSContextBase() { }

    public StaticTSContextBase(ParserRuleContext parent, int invokingStateNumber) {
        super(parent, invokingStateNumber);
    }

    public void addLeadingComment(TerminalNode stsComment) {
        if (leadingComments == null) leadingComments = new LinkedList<>();
        leadingComments.add(stsComment);
    }

    public void addTrailingComment(TerminalNode stsComment) {
        if (trailingComments == null) trailingComments = new LinkedList<>();
        trailingComments.add(stsComment);
    }

    public void setLeadingComments(List<TerminalNode> stsComments) {
        leadingComments = stsComments;
    }

    public void setTrailingComments(List<TerminalNode> stsComments) {
        trailingComments = stsComments;
    }

    public List<TerminalNode> getLeadingComments() {
        return leadingComments;
    }

    public List<TerminalNode> getTrailingComments() {
        return trailingComments;
    }

    public boolean hasLeadingComments() {
        return leadingComments != null && !leadingComments.isEmpty();
    }

    public boolean hasTrailingComments() {
        return trailingComments != null && !trailingComments.isEmpty();
    }
}
