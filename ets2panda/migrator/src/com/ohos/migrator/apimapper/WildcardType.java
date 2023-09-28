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
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.WildcardTypeContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.TypeArgumentContext;
import static com.ohos.migrator.apimapper.Util.isStringEmpty;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

//  <WildcardType>
//      <WildcardBound type="in or out"> // Optional bounds. If it's not specified then only a question mark will be used as the wildcard type.
//          <TypeReference/>             // Look TypeReference class for details.
//      </WildcardBound>
//  </WildcardType>
public class WildcardType {
    static public String tag = "WildcardType";
    private String type = null;
    private TypeReference typeReference = null;

    static WildcardType read(XMLEventReader xmlReader, XMLEvent xmlWildcardTypeEvent) throws XMLStreamException {
        WildcardType wildcardType = new WildcardType();

        if (!xmlWildcardTypeEvent.isEndElement()) {
            while (xmlReader.hasNext()) {
                XMLEvent xmlEvent = xmlReader.nextEvent();

                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    String tag = startElement.getName().getLocalPart();

                    if ("WildcardBound".equals(tag)) {
                        wildcardType.type = Util.getAttribute(startElement, Util.typeAttr);
                    }
                    else if (TypeReference.tag.equals(tag)) {
                        wildcardType.typeReference = TypeReference.read(xmlReader, xmlEvent);
                    }
                    else
                        assert false;
                }
                else if (xmlEvent.isEndElement()) {
                    EndElement endElement = xmlEvent.asEndElement();
                    String tag = endElement.getName().getLocalPart();

                    if (WildcardType.tag.equals(tag)) {
                        break;
                    }
                    else {
                        assert ("WildcardBound".equals(tag) || TypeReference.tag.equals(tag));
                    }
                }
            }
        }

        return wildcardType;
    }

    // ArkTS:
    // wildcardType
    //    : { this.next(IN) }? Identifier typeReference
    //    | { this.next(OUT) }? Identifier typeReference?

    // List<TypeArgumentContext> arktsOrigTypeArguments
    public WildcardTypeContext buildArktsNode(List<TypeArgumentContext> arktsOrigTypeArguments) {
        WildcardTypeContext arktsWildcardType = new WildcardTypeContext(null, 0);

        if (isStringEmpty(type)) {
            assert (type.equals(StaticTSParser.OUT) || type.equals(StaticTSParser.IN));

            arktsWildcardType.addChild(NodeBuilder.terminalIdentifier(type));

            if (typeReference != null) {
                arktsWildcardType.addChild(typeReference.buildArktsNode(arktsOrigTypeArguments)).setParent(arktsWildcardType);
            }
        }

        return arktsWildcardType;
    }
}
