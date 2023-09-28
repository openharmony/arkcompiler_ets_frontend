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

// <Literal type="null OR boolean OR string OR char OR decimal OR hexInteger OR octalInteger OR binaryInteger" value="proper_value"/>

import com.ohos.migrator.java.NodeBuilder;
import com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;

import static com.ohos.migrator.apimapper.Util.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

public class Literal {
    static public String tag = "Literal";

    private enum Type {
        NULL, BOOLEAN, STRING, CHAR, DECIMAL, HEXINTEGER, OCTALINTEGER, BINARYINTEGER
    }

    private Type type;
    private String value = null;

    static private QName typeAttr = new QName("type");

    static Literal read(XMLEventReader xmlReader, XMLEvent xmlLiteralEvent) throws XMLStreamException {
        Literal literal = new Literal();

        assert  (xmlLiteralEvent.isStartElement());
        StartElement startElement = xmlLiteralEvent.asStartElement();

        String tp = Util.getAttribute(startElement, typeAttr);

        if ("null".equals(tp)) {
            literal.type = Type.NULL;
        }
        else if ("boolean".equals(tp)) {
            literal.type = Type.BOOLEAN;
        }
        else if ("string".equals(tp)) {
            literal.type = Type.STRING;
        }
        else if ("char".equals(tp)) {
            literal.type = Type.CHAR;
        }
        else if ("decimal".equals(tp)) {
            literal.type = Type.DECIMAL;
        }
        else if ("hexInteger".equals(tp)) {
            literal.type = Type.HEXINTEGER;
        }
        else if ("octalInteger".equals(tp)) {
            literal.type = Type.OCTALINTEGER;
        }
        else if ("binaryInteger".equals(tp)) {
            literal.type = Type.BINARYINTEGER;
        }
        else {
            assert false;
        }

        literal.value = getAttribute(startElement, valueAttr);

        // Read the <Literal/> end event.
        assert (xmlReader.hasNext());
        XMLEvent xmlEvent = xmlReader.nextEvent();
        assert xmlEvent.isEndElement();
        EndElement endElement = xmlEvent.asEndElement();
        assert Literal.tag.equals(endElement.getName().getLocalPart());

        return literal;
    }

    public SingleExpressionContext buildArktsNode() {
        switch (type) {
            case NULL: return NodeBuilder.nullLiteral();
            case BOOLEAN: return NodeBuilder.boolLiteral(Boolean.parseBoolean(value));
            case STRING: return NodeBuilder.stringLiteral(value);
            case CHAR: return NodeBuilder.charLiteral(value);
            case DECIMAL:
            case HEXINTEGER:
            case OCTALINTEGER:
            case BINARYINTEGER: return NodeBuilder.numericLiteral(value);
        }

        assert false;
        return null;
    }
}
