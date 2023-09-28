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

import org.antlr.v4.runtime.*;

/**
 * All parser methods that used in grammar (p, prev, notLineTerminator, etc.)
 * should start with lower case char similar to parser rules.
 */
public abstract class StaticTSParserBase extends Parser
{
    // These are context-dependent keywords, i.e. those that
    // can't be used as identifiers only in specific contexts

    public static final String CATCH = "catch"; // keyword in try statement context

    public static final String DEFAULT = "default"; // keyword in switch statement context

    public static final String EXTENDS = "extends"; // keyword in class/interface declaration context

    public static final String FROM = "from"; // keyword in import declaration context

    public static final String GET = "get"; // keyword in accessor declaration context

    public static final String IMPLEMENTS = "implements"; // keyword in class declaration context
    public static final String IN = "in"; // keyword in type argument and type parameter contexts

    public static final String OF = "of"; // keyword in for statement context
    public static final String OUT = "out"; // keyword in type argument and type parameter contexts

    public static final String READONLY = "readonly"; // keyword in field declaration context
    public static final String RETHROWS = "rethrows"; // keyword in function/method declaration context

    public static final String SET = "set"; // keyword in accessor declaration context
    public static final String THROWS = "throws"; // keyword in function/method declaration context

    // The following keywords are reserved for use as predefined type names
    // and cannot appear as user-defined type names; otherwise, they can be
    // used freely as identifiers.
    public static final String BOOLEAN = "boolean";
    public static final String BYTE = "byte";
    public static final String CHAR = "char";
    public static final String DOUBLE = "double";
    public static final String FLOAT = "float";
    public static final String INT = "int";
    public static final String LONG = "long";
    public static final String SHORT = "short";
    public static final String UBYTE = "ubyte";
    public static final String UINT = "uint";
    public static final String ULONG = "ulong";
    public static final String USHORT = "ushort";
    public static final String VOID = "void";
    private static final String[] predefinedTypeNames = {
            BOOLEAN, BYTE, CHAR, DOUBLE, FLOAT, INT, LONG,
            SHORT, UBYTE, UINT, ULONG, USHORT, VOID
    };
    public StaticTSParserBase(TokenStream input) {
        super(input);
    }

    /**
     * Short form for prev(String str)
     */
    protected boolean p(String str) {
        return prev(str);
    }

    /**
     * Whether the previous token value equals to @param str
     */
    protected boolean prev(String str) {
        return _input.LT(-1).getText().equals(str);
    }

    /**
     * Short form for next(String str)
     */
    protected boolean n(String str) {
        return next(str);
    }

    /**
     * Whether the next token value equals to @param str
     */
    protected boolean next(String str) {
        return _input.LT(1).getText().equals(str);
    }

    protected boolean notLineTerminator() {
        return !here(StaticTSParser.LineTerminator);
    }

    protected boolean predefinedTypeAhead() {
        for (String predefTypeName : predefinedTypeNames) {
            if (next(predefTypeName)) return true;
        }

        return false;
    }

    protected boolean notOpenBraceAndNotFunction() {
        int nextTokenType = _input.LT(1).getType();
        return nextTokenType != StaticTSParser.OpenBrace && nextTokenType != StaticTSParser.Function;
    }
    protected boolean closeBrace() {
        return _input.LT(1).getType() == StaticTSParser.CloseBrace;
    }
    
    /**
     * Returns {@code true} iff on the current index of the parser's
     * token stream a token of the given {@code type} exists on the
     * {@code HIDDEN} channel.
     *
     * @param type
     *         the type of the token on the {@code HIDDEN} channel
     *         to check.
     *
     * @return {@code true} iff on the current index of the parser's
     * token stream a token of the given {@code type} exists on the
     * {@code HIDDEN} channel.
     */
    private boolean here(final int type) {

        // Get the token ahead of the current index.
        int possibleIndexEosToken = this.getCurrentToken().getTokenIndex() - 1;
        Token ahead = _input.get(possibleIndexEosToken);

        // Check if the token resides on the HIDDEN channel and if it's of the
        // provided type.
        return (ahead.getChannel() == Lexer.HIDDEN) && (ahead.getType() == type);
    }
    
    /**
     * Returns {@code true} iff on the current index of the parser's
     * token stream a token exists on the {@code HIDDEN} channel which
     * either is a line terminator, or is a multi line comment that
     * contains a line terminator.
     *
     * @return {@code true} iff on the current index of the parser's
     * token stream a token exists on the {@code HIDDEN} channel which
     * either is a line terminator, or is a multi line comment that
     * contains a line terminator.
     */
    protected boolean lineTerminatorAhead() {

        // Get the token ahead of the current index.
        int possibleIndexEosToken = this.getCurrentToken().getTokenIndex() - 1;
        Token ahead = _input.get(possibleIndexEosToken);

        if (ahead.getChannel() != Lexer.HIDDEN) {
            // We're only interested in tokens on the HIDDEN channel.
            return false;
        }

        if (ahead.getType() == StaticTSParser.LineTerminator) {
            // There is definitely a line terminator ahead.
            return true;
        }

        if (ahead.getType() == StaticTSParser.WhiteSpaces) {
            // Get the token ahead of the current whitespaces.
            possibleIndexEosToken = this.getCurrentToken().getTokenIndex() - 2;
            ahead = _input.get(possibleIndexEosToken);
        }

        // Get the token's text and type.
        String text = ahead.getText();
        int type = ahead.getType();

        // Check if the token is, or contains a line terminator.
        return (type == StaticTSParser.MultiLineComment && (text.contains("\r") || text.contains("\n"))) ||
                (type == StaticTSParser.LineTerminator);
    }
}
