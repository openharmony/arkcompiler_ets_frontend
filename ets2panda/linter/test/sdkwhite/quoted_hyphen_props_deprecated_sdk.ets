/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { rcp } from '@kit.RemoteCommunicationKit';
import { externalRequestHeaders,externalRequestHeadersInterface } from './quoted_hyphen_props_deprecated_sdk2';
import { externalResponseHeaders,externalResponseHeadersInterface } from './quoted_hyphen_props_deprecated_sdk2';
export interface internalRequestHeaders<T extends object> {
  rcpHeaders: rcp.RequestHeaders;
  additionalHeaders: T;
}
interface AdditionalHeaders {
  customHeader: string;
}
type CustomRequestHeaders = internalRequestHeaders<AdditionalHeaders>;
const cusRequestHeaders: CustomRequestHeaders = {
  rcpHeaders: {
    'content-type': 'application/json', // Error
     range: 'bytes=0-1023' // Error
  },
  additionalHeaders: {
    customHeader: 'custom value'
  }
};
const basicHeaders: rcp.RequestHeaders = {
  'authorization': 'Bearer abc123', // Error
  'content-type': 'application/json' // Error
};
basicHeaders.cookie =''; // Error
function createHeaders(cookie:string,authToken?: string): rcp.RequestHeaders {
  return {
    'authorization': authToken ? `Bearer ${authToken}` : undefined, // Error
    'accept': 'application/json', // Error
    'cache-control': 'no-cache', // Error
    'user-agent': 'MyApp/2.0' // Error
  };
}
createHeaders(basicHeaders.cookie); // Error
function getRange(){
  return basicHeaders.range; // Error
}

export type localRequestHeaders = rcp.RequestHeaders;
let localHeaders:localRequestHeaders = {
  'accept-charset': 'UTF-8', // Error
  'accept-encoding': 'gzip, deflate', // Error
  'accept-language': 'en-US,en;q=0.9', // Error
  'cookie': 'session_id=123456', // Error
  'range': 'bytes=0-1023', // Error
  'upgrade': 'websocket', // Error
  'content-type':'application/json' // Error
}
let externalHeaders:externalRequestHeaders = {
  cookie: 'session_id=123456', // Error
  range: 'bytes=0-1023', // Error
  'content-type':'application/json' // Error
}
const setRequestHeaders1 = (headers: externalRequestHeaders) => {
  headers.authorization =''; // Error
}
class RemoteTest{
  setCookie(cookie:string){
    cookie = 'cookie'
  }
  createHeaders(cookie:string,authToken?: string): rcp.RequestHeaders {
    return {
      authorization: authToken ? `Bearer ${authToken}` : undefined, // Error
      accept: 'application/json', // Error
      "cache-control": 'no-cache', 
      "user-agent": 'MyApp/2.0', 
      upgrade:'web', // Error
      range:'' // Error
    };
  }
  constructor() {
    createHeaders(basicHeaders.authorization!); // Error
  }
}
const exRequestHeadersInterface: externalRequestHeadersInterface = {
  authorization: 'Bearer token', //Error
  customHeader1: 'value1'
};
function processHeaders(headers: externalRequestHeadersInterface) {
  console.log(headers.authorization); //Error
  console.log(headers.customHeader1);
}
function createExHeaders(): externalRequestHeadersInterface {
  return {
    authorization: 'Bearer token', //Error
    customHeader1: 'value1'
  };
}
typeof exRequestHeadersInterface.authorization; //Error
console.log('accept='+exRequestHeadersInterface.accept) //Error
function printHeaders<T extends externalRequestHeadersInterface>(exheaders: externalRequestHeadersInterface) {
  console.log(exheaders.authorization); //Error
}
const headersArray: externalRequestHeadersInterface[] = [
  {
    authorization: 'application/json', //Error
    customHeader1: 'header1Value1'
  },
  {
    'cookie': 'sss', //Error
    customHeader1: 'header1Value2'
  }
];
interface RequestConfig {
  headers: externalRequestHeadersInterface;
  url: string;
  method: 'GET' | 'POST';
}

const config: RequestConfig = {
  headers: {
    'authorization': 'application/json', //Error
    customHeader1: 'configHeaderValue'
  },
  url: 'https://example.com/api',
  method: 'GET'
};
export const headers:string[]=[
  'authorization',
  'accept',
  'cache-control',
  'user-agent',
  'accept-charset',
  'accept-encoding',
  'accept-language',
  'cookie',
  'range',
  'upgrade',
  'content-type'
]

//ResponseHeader part
let externalResponseHeader:externalResponseHeaders = {
  'accept-ranges':'',  // Error
  'allow': '',  // Error
  'cache-control': '',  // Error
  'content-encoding': ''  // Error
}
const setResponseHeaders = (headers: externalResponseHeaders) => {
  headers.expires ='';  // Error
}

const exResponseHeadersInterface: externalResponseHeadersInterface = {
  "www-authenticate": 'Bearer token',
  customHeader2: 'value1'
};
function processResponseHeaders(responseHeaders: externalResponseHeadersInterface) {
  console.log(responseHeaders.date);  // Error
  console.log(responseHeaders.customHeader2);
}
function createExResponseHeaders(): externalResponseHeadersInterface {
  return {
    date: '2025', //Error
    customHeader2: 'value1'
  };
}
typeof exResponseHeadersInterface.authorization; //Error
console.log('accept='+exResponseHeadersInterface.accept) //Error
function printResponseHeaders<T extends externalResponseHeadersInterface>(exHeaders: externalResponseHeadersInterface) {
  console.log(exHeaders.etag); //Error
}
const responseHeadersArray: externalResponseHeadersInterface[] = [
  {
    "cache-control": 'application/json',
    customHeader2: 'header1Value1'
  },
  {
    'server': 'sss', //Error
    customHeader2: 'header1Value2'
  }
];
interface ResponseConfig {
  headers: externalResponseHeadersInterface;
  url: string;
  method: 'GET' | 'POST';
}

const config2: ResponseConfig = {
  headers: {
    'content-encoding': 'application/json', //Error
    customHeader2: 'configHeaderValue'
  },
  url: 'https://example.com/api',
  method: 'GET'
};