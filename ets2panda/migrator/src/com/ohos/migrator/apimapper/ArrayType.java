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
import com.ohos.migrator.staticTS.parser.StaticTSParser.ArrayTypeContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.TypeArgumentContext;

import static com.ohos.migrator.apimapper.Util.tagPredefinedType;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

//  <ArrayType>
//      <PredefinedType name="byte OR ubite OR short OR ushort OR int OR uint OR long OR ulong OR float OR double OR boolean OR string OR char OR void"/>
//      // OR
//      <TypeReference/>
//  </ArrayType>
public class ArrayType {
    static public String tag = "ArrayType";
    private String predefinedType = null;
    private TypeReference typeReference = null;

    static ArrayType read(XMLEventReader xmlReader) throws XMLStreamException {
        ArrayType arrayType = new ArrayType();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (tagPredefinedType.equals(tag)) {
                    arrayType.predefinedType = Util.getAttribute(startElement, Util.nameAttr);
                }
                else if (TypeReference.tag.equals(tag)) {
                    arrayType.typeReference = TypeReference.read(xmlReader, xmlEvent);
                }
                else assert false : "Unexpected XmlElement " + tag;
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (ArrayType.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (tagPredefinedType.equals(tag) || TypeReference.tag.equals(tag));
                }
            }
        }

        return arrayType;
    }

    // ArkTS:
    //  arrayType: (predefinedType | typeReference) {notLineTerminator()}? (OpenBracket CloseBracket)+
    // The rule:
    //  <ArrayType>
    //      <PredefinedType name="byte OR ubyte OR short OR ushort OR int OR uint OR long OR ulong OR float OR double OR boolean OR string OR char OR void"/>
    //      // OR
    //      <TypeReference/>-->
    //   </ArrayType>
    public ArrayTypeContext buildArktsNode(List<TypeArgumentContext> arktsOrigTypeArguments) {
        ArrayTypeContext arktsArrayType = new ArrayTypeContext(null, 0);

        if (predefinedType != null) {
            arktsArrayType.addChild(NodeBuilder.predefinedType(predefinedType));
        }
        else {
            assert (typeReference != null);
            arktsArrayType.addChild(typeReference.buildArktsNode(arktsOrigTypeArguments)).setParent(arktsArrayType);
        }

        arktsArrayType.addChild(NodeBuilder.terminalNode(StaticTSParser.OpenBracket));
        arktsArrayType.addChild(NodeBuilder.terminalNode(StaticTSParser.CloseBracket));

        return arktsArrayType;
    }
}
