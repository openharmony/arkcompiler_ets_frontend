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

package com.ohos.migrator.apimapper;

import com.ohos.migrator.java.NodeBuilder;
import com.ohos.migrator.staticTS.NodeClonner;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.UnaryPlusExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.UnaryMinusExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.NotExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.BitNotExpressionContext;

import static com.ohos.migrator.apimapper.Util.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

public class UnaryExpression {
    static public String tag = "UnaryExpression";
    private enum Operation {
        MINUS, PLUS, BIT_NOT, NOT
    }

    private int index = -1;
    private Operation operation;

    static UnaryExpression read(XMLEventReader xmlReader, XMLEvent xmlUnaryExpressionEvent) throws XMLStreamException {
        UnaryExpression unaryExpression = new UnaryExpression();

        assert xmlUnaryExpressionEvent.isStartElement();
        StartElement startElement = xmlUnaryExpressionEvent.asStartElement();

        unaryExpression.index = Integer.valueOf(getAttribute(startElement, indexAttr));

        String op = getAttribute(startElement, operationAttr);

        if ("+".equals(op)) {
            unaryExpression.operation = Operation.PLUS;
        } else if ("-".equals(op)) {
            unaryExpression.operation = Operation.MINUS;
        } else if ("~".equals(op)) {
            unaryExpression.operation = Operation.BIT_NOT;
        } else if ("!".equals(op)) {
            unaryExpression.operation = Operation.NOT;
        } else {
            assert false;
        }

        // Read the <UnaryExpression/> end event.
        assert (xmlReader.hasNext());
        XMLEvent xmlEvent = xmlReader.nextEvent();
        assert xmlEvent.isEndElement();
        EndElement endElement = xmlEvent.asEndElement();
        assert UnaryExpression.tag.equals(endElement.getName().getLocalPart());

        return unaryExpression;
    }

    public SingleExpressionContext buildArktsNode(List<SingleExpressionContext> arktsOrigArguments) {
        assert (index >= 0);
        assert (arktsOrigArguments != null);
        assert (arktsOrigArguments.size() > index);

        SingleExpressionContext arktsUnaryExprParent = new SingleExpressionContext();
        SingleExpressionContext arktsUnaryExpr = null;

        int arktsOpType = -1;

        switch (operation)
        {
            case PLUS:
                arktsUnaryExpr = new UnaryPlusExpressionContext(arktsUnaryExprParent);
                arktsOpType = StaticTSParser.Plus;
                break;

            case MINUS:
                arktsUnaryExpr = new UnaryMinusExpressionContext(arktsUnaryExprParent);
                arktsOpType = StaticTSParser.Minus;
                break;

            case NOT:
                arktsUnaryExpr = new NotExpressionContext(arktsUnaryExprParent);
                arktsOpType = StaticTSParser.Not;
                break;

            case BIT_NOT:
                arktsUnaryExpr = new BitNotExpressionContext(arktsUnaryExprParent);
                arktsOpType = StaticTSParser.BitNot;
                break;
        }

        assert (arktsUnaryExpr != null);

        arktsUnaryExpr.addChild(NodeBuilder.terminalNode(arktsOpType));

        arktsUnaryExpr.addChild(NodeClonner.clone(arktsOrigArguments.get(index))).setParent(arktsUnaryExpr);

        arktsUnaryExprParent.addChild(arktsUnaryExpr).setParent(arktsUnaryExprParent);

        return arktsUnaryExprParent;
    }
}
