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

package com.ohos.migrator.staticTS;

import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.Token;

import java.util.ArrayList;
import java.util.List;


public class SyntaxErrorListener extends BaseErrorListener {
    List<String> msgList;
    public List<String> getMsgList() { return msgList; }

    public void clearMsgList() { msgList = new ArrayList<>();}

    public static final SyntaxErrorListener INSTANCE = new SyntaxErrorListener();

    public SyntaxErrorListener() { clearMsgList(); }

    @Override
    public void syntaxError(Recognizer<?,?> recognizer, Object offendingsymbol, int line, int charPositionInLine, String msg, RecognitionException e) {
        msgList.add("line " + line + ":" + charPositionInLine + " " + msg);
    }

    public void notifyError(Token offendingToken, String msg, RecognitionException e) {
        int line = offendingToken.getLine();
        int charPositionInLine = offendingToken.getCharPositionInLine();
        msgList.add("line " + line + ":" + charPositionInLine + " " + msg);
    }
}
