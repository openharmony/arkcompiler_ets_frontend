/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {createSourceFile, ScriptTarget} from 'typescript';
import type {Node, SourceFile, Statement} from 'typescript';
import {NodeUtils} from './NodeUtils';

export abstract class BaseEncryptedHelper {
  protected constructor() {
  }

  public abstract encode(content: string): string;

  public abstract decode(content: string): string;

  public abstract decodeStruct(names: string[]): Node;
}

export class Base64Helper extends BaseEncryptedHelper {
  public constructor() {
    super();
  }

  /**
   * @param content
   */
  public encode(content: string): string {
    try {
      return Buffer.from(encodeURIComponent(content), 'utf-8').toString('base64');
    } catch (e) {
      return null;
    }
  }

  /**
   * @param content
   */
  public decode(content: string): string {
    let decodedContent: string = decodeURI(content);
    let _keyStr: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let output: string = '';
    let chr1: number;
    let chr2: number;
    let chr3: number;
    let enc1: number;
    let enc2: number;
    let enc3: number;
    let enc4: number;
    let i: number = 0;

    decodedContent = decodedContent.replace(/[^A-Za-z0-9\+\/\=]/g, '');
    while (i < decodedContent.length) {
      enc1 = _keyStr.indexOf(decodedContent.charAt(i++));
      enc2 = _keyStr.indexOf(decodedContent.charAt(i++));
      enc3 = _keyStr.indexOf(decodedContent.charAt(i++));
      enc4 = _keyStr.indexOf(decodedContent.charAt(i++));
      chr1 = (enc1 << 2) | (enc2 >> 4);
      chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
      chr3 = ((enc3 & 3) << 6) | enc4;
      output = output + String.fromCharCode(chr1);
      if (enc3 !== 64) {
        output = output + String.fromCharCode(chr2);
      }

      if (enc4 !== 64) {
        output = output + String.fromCharCode(chr3);
      }
    }

    return decodeURIComponent(output);
  }

  public decodeStruct(names: string[]): Statement {
    let code: string = `
            let ${names[0]} =function (${names[1]}) {
                ${names[1]} = decodeURIComponent(${names[1]});
                let ${names[2]} = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',${names[3]} = '',${names[4]} = 0;
                   
                ${names[1]} = ${names[1]}.replace(/[^A-Za-z0-9\\+\\/\\=]/g, '');
                while (${names[4]} < ${names[1]}.length) {
                    let ${names[5]} = ${names[2]}.indexOf(${names[1]}.charAt(${names[4]}++));
                    let ${names[6]} = ${names[2]}.indexOf(${names[1]}.charAt(${names[4]}++));
                    let ${names[7]} = ${names[2]}.indexOf(${names[1]}.charAt(${names[4]}++));
                    let ${names[8]} = ${names[2]}.indexOf(${names[1]}.charAt(${names[4]}++));
                    ${names[3]} += String.fromCharCode((${names[5]} << 2) | (${names[6]} >> 4));
                    ${names[3]} += (${names[7]} >> 6 === 1) ? '' : String.fromCharCode(((${names[6]} & 15) << 4) | (${names[7]} >> 2));
                    ${names[3]} += (${names[8]} >> 6 === 1) ? '' : String.fromCharCode(((${names[7]} & 3) << 6) | ${names[8]});
                }
                return decodeURIComponent(${names[3]});
            }
        `;

    let source: SourceFile = createSourceFile('', code, ScriptTarget.ES2015, true);
    return NodeUtils.setSynthesis(source.statements[0]);
  }
}
