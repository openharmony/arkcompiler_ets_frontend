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

import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.IntervalSet;

public class CheckerErrorStrategy extends DefaultErrorStrategy {

    @Override
    public void reportError(Parser parser, RecognitionException e) {
        if( !inErrorRecoveryMode(parser)) {
            beginErrorCondition(parser);
            if( e instanceof NoViableAltException) {
                reportNoViableAlternative(parser, (NoViableAltException)e);
            } else if( e instanceof InputMismatchException) {
                reportInputMismatch(parser, (InputMismatchException)e);
            } else if( e instanceof FailedPredicateException) {
                reportFailedPredicate(parser, (FailedPredicateException)e);
            } else {
                SyntaxErrorListener.INSTANCE.notifyError(e.getOffendingToken(), e.getMessage(), e);
            }
        }
    }

    @Override
    protected void reportNoViableAlternative(Parser parser, NoViableAltException e) {
        TokenStream tokens = parser.getInputStream();
        String input;
        if( tokens != null) {
            if( e.getStartToken().getType() == -1 ) {
                input = "<EOF>";
            } else {
                input = tokens.getText(e.getStartToken(), e.getOffendingToken());
            }
        } else {
            input = "<unknown input>";
        }

        String msg = "no viable alternative at input " + escapeWSAndQuote(input);
        SyntaxErrorListener.INSTANCE.notifyError(e.getOffendingToken(), msg, e);
    }

    @Override
    protected void reportInputMismatch(Parser parser, InputMismatchException e) {
        String msg = "mismatched input " + getTokenErrorDisplay(e.getOffendingToken()) + " expecting " + e.getExpectedTokens().toString(parser.getVocabulary());
        SyntaxErrorListener.INSTANCE.notifyError(e.getOffendingToken(), msg, e);
    }

    @Override
    protected void reportFailedPredicate(Parser parser, FailedPredicateException e) {
        String ruleName = parser.getRuleNames()[parser.getContext().getRuleIndex()];
        String msg = "rule " + ruleName + " " + e.getMessage();
        SyntaxErrorListener.INSTANCE.notifyError(e.getOffendingToken(), msg, e);
    }

    @Override
    protected void reportUnwantedToken(Parser parser) {
        if( !inErrorRecoveryMode(parser)) {
            beginErrorCondition(parser);
            Token t = parser.getCurrentToken();
            String tokenName = parser.getTokenErrorDisplay(t);
            IntervalSet expecting = getExpectedTokens(parser);
            String msg = "extraneous input " + tokenName + " expecting " + expecting.toString(parser.getVocabulary());
            SyntaxErrorListener.INSTANCE.notifyError(t, msg, null);
        }
    }

    @Override
    protected void reportMissingToken(Parser parser) {
        if( !inErrorRecoveryMode(parser)) {
            beginErrorCondition(parser);
            Token t = parser.getCurrentToken();
            IntervalSet expecting = getExpectedTokens(parser);
            String msg = "missing " + expecting.toString(parser.getVocabulary()) + " at " + getTokenErrorDisplay(t);
            SyntaxErrorListener.INSTANCE.notifyError(t, msg, (RecognitionException) null);
        }
    }

}
