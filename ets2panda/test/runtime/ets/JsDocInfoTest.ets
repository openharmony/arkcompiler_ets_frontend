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

/**
* JsDocTest on namespace
*
* @JsDocRecord1 comments
* @JsDocRecord2 { JsDocRecord1 param } comments
* @JsDocRecord3 {} comments
*/
namespace ns {
  /**
  * JsDocTest on interface.
  *
  * @JsDocRecord1 comments
  * @JsDocRecord2 { JsDocRecord1 param } comments
  * @JsDocRecord3 {} comments
  */
  export interface itfc1 {
    /**
    * JsDocTest on method.
    *
    * @JsDocRecord1 comments
    * @JsDocRecord2 { JsDocRecord1 'param' } comments
    * @JsDocRecord3 {} comments
    */
    foo():void

    /**
    * JsDocTest on prop.
    *
    * @JsDocRecord1 comments
    * @JsDocRecord2 { JsDocRecord1 'param' } comments
    * @JsDocRecord3 {} comments
    */
    prop:number
  }

  /**
  * JsDocTest on class.
  *
  * @JsDocRecord1 comments
  * @JsDocRecord2 { JsDocRecord1 param } comments
  * @JsDocRecord3 {} comments
  */
  export class cls {
    /**
    * JsDocTest on method.
    *
    * @JsDocRecord1 comments
    * @JsDocRecord2 { JsDocRecord1 'param' } comments
    * @JsDocRecord3 {} comments
    */
    foo():void {}

    /**
    * JsDocTest on prop.
    *
    * @JsDocRecord1 comments
    * @JsDocRecord2 { JsDocRecord1 'param' } comments
    * @JsDocRecord3 {} comments
    */
    prop:number
  }

  /**
  * JsDocTest on namespace
  *
  * @JsDocRecord1 comments
  * @JsDocRecord2 { JsDocRecord1 param } comments
  * @JsDocRecord3 {} comments
  */
  namespace ns_inner {}
}

/**
 * JsDocTest on interface.
 *
 * @JsDocRecord1 comments
 * @JsDocRecord2 { JsDocRecord1 param } comments
 * @JsDocRecord3 {} comments
 */
export interface itfc1 {
  /**
  * JsDocTest on method.
  *
  * @JsDocRecord1 comments
  * @JsDocRecord2 { JsDocRecord1 'param' } comments
  * @JsDocRecord3 {} comments
  */
  foo():void

  /**
  * JsDocTest on prop.
  *
  * @JsDocRecord1 comments
  * @JsDocRecord2 { JsDocRecord1 'param' } comments
  * @JsDocRecord3 {} comments
  */
  prop:number
}



/**
 * JsDocTest on class.
 *
 * @JsDocRecord1 comments
 * @JsDocRecord2 { JsDocRecord1 param } comments
 * @JsDocRecord3 {} comments
 */
export class cls {
  /**
  * JsDocTest on method.
  *
  * @JsDocRecord1 comments
  * @JsDocRecord2 { JsDocRecord1 'param' } comments
  * @JsDocRecord3 {} comments
  */
  foo():void {}

  /**
  * JsDocTest on prop.
  *
  * @JsDocRecord1 comments
  * @JsDocRecord2 { JsDocRecord1 'param' } comments
  * @JsDocRecord3 {} comments
  */
  prop:number
}

/**
* JsDocTest on arrow function.
*
* @JsDocRecord1 comments
* @JsDocRecord2 { JsDocRecord1 'param' } comments
* @JsDocRecord3 {} comments
*/
let arrowFunc:() => void = ():void => {}

/**
* JsDocTest on function decl.
*
* @JsDocRecord1 comments
* @JsDocRecord2 { JsDocRecord1 'param' } comments
* @JsDocRecord3 {} comments
*/
function testFunc():void {}

/**
* JsDocTest on typeAlias.
*
* @JsDocRecord1 comments
* @JsDocRecord2 { JsDocRecord1 'param' } comments
* @JsDocRecord3 {} comments
*/
type xx =
/**
* @xx {xx} xx
*/
'somexx'
/**
* @xx {xx} xx
*/
| 'somexx2'
/**
* @xx {xx} xx
*/
| 'somexx3'

function main() {
  /**
  * JsDocTest on arrow variable decl.
  *
  * @JsDocRecord1 comments
  * @JsDocRecord2 { JsDocRecord1 'param' } comments
  * @JsDocRecord3 {} comments
  */
  let val:string = "ssss"
  assertTrue(true);
  assertEQ(val, "ssss")
}