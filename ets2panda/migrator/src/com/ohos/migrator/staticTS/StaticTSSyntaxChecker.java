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

import com.ohos.migrator.AbstractTranspiler;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.TranspileException;
import com.ohos.migrator.staticTS.parser.*;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.ParseCancellationException;

import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class StaticTSSyntaxChecker extends AbstractTranspiler {
    // currently no libs are needed but may be in future...
    public StaticTSSyntaxChecker(List<File> src, List<File> libs) {
        super(src, libs, null);
    }

    @Override
    public void transpileFile(File srcFile) throws TranspileException {
        boolean syntaxOK = false;
        try {
            CharStream input = CharStreams.fromFileName(srcFile.getAbsolutePath());
            StaticTSLexer lexer = new StaticTSLexer(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            StaticTSParser parser = new StaticTSParser(tokens);
            parser.setErrorHandler(new CheckerErrorStrategy());
            parser.removeParseListeners();

            parser.compilationUnit();
            List<String> msgList = SyntaxErrorListener.INSTANCE.getMsgList();
            if( !msgList.isEmpty()) {
                throw new TranspileException(ResultCode.ParseError, new SyntaxCheckException(msgList));
            }

            syntaxOK = true;
        } catch (IOException e) {
            throw new TranspileException(ResultCode.InputError, e);
        } catch (RecognitionException e) {
            throw new TranspileException(ResultCode.ParseError, "File " + srcFile.getPath() + " failed syntax check!");
        } catch (ParseCancellationException e) {
            throw new TranspileException(ResultCode.ParseError, "File " + srcFile.getPath() + " failed syntax check!");
        }  finally {
            if (!syntaxOK) outFiles.add(srcFile);
            SyntaxErrorListener.INSTANCE.clearMsgList();
	    }
    }

    @Override
    protected void writeUntranslatedFile(File srcFile) {
        // Do nothing, as we're not translating here.
    }
}
