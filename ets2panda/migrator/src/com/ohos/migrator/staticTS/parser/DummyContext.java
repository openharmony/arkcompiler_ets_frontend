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

import com.ohos.migrator.staticTS.writer.StaticTSWriter;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTreeVisitor;

public class DummyContext extends StaticTSContextBase {
    public DummyContext() { }

    public DummyContext(ParserRuleContext parent, int invokingStateNumber) {
        super(parent, invokingStateNumber);
    }

    @Override
    public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
        if (visitor instanceof StaticTSWriter) {
            ((StaticTSWriter) visitor).visitDummyNode(this);
            return null;
        }
        return visitor.visitChildren(this);
    }
}
