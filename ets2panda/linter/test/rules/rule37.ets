/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

 let regex: RegExp = /bc*d/;

 let regex2: RegExp = new RegExp("bc*d");

 const regex3 = /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
 const regex4: RegExp = new RegExp('^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$');

 let regex5: RegExp = /bc*d/ig;

 let regex6: RegExp = new RegExp("bc*d", "ig");

 let regex7: RegExp = new RegExp(/bc*d/i, "g");

 let regex8: RegExp = new RegExp(new RegExp("bc*d", "i"), "g");

 let regex9: RegExp = /a\\/;

 let regex10: RegExp = new RegExp("a\\\\");

 class A {
     static readonly classregex0: RegExp = /bc*d/
 
     static readonly classregex2 = /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
 
     classregex3: RegExp = new RegExp("bc*d");
 
     static staticMethodOne() {
         let regex = /bc*d/
     }
 
     static staticMethodTwo() {
         let regex: RegExp = new RegExp("/bc*d/");
     }

     methodOne() {
         let regex = /bc*d/
     }

     methodTwo() {
         let regex: RegExp = new RegExp("/bc*d/");
     }
 
     methodRet(): RegExp {
         return /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
     }
 }

 const regexLambda = () => /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;

 let regex12: RegExp = RegExp("ab*c")

 let regex13: RegExp = RegExp("ab*c","i")

 let a27: RegExp = RegExp('dawfgr'+'12345')

 let a25: RegExp = RegExp('.∗?(?:(?:元宵|三八|妇女|母亲|父亲|七夕|重阳|情人|儿童|六一'+'|愚人|复活|青年|护士|建军|教师|建党|万圣|感恩|秘书|七一|五四|八一|腊八|光棍|植树|中元)节|除夕|大年三十|大年30|七夕'+'|平安夜|六一|七一|五四|八一|三八|腊八|双十一|双十二).∗');

 let regex20: RegExp = RegExp('dawfgr'.concat('12345')) 

  let a28: RegExp = RegExp('dawfgr'+'12345' + '789') 
