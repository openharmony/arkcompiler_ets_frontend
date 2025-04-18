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
 
'use static'
import myAaa,{ClassA,Dog,Person,Wiki} from "./interop_import_js_js";
import { Dog as Doge } from './interop_import_js_js';
import { Wiki as wiki } from './interop_import_js_js';

typeof myAaa(); //error
let fun = myAaa();
typeof fun;
typeof Dog; //error
typeof Dog('doge'); //error
typeof Doge('doge'); //error
typeof Wiki //error
typeof Wiki.name //error
typeof wiki //error
let val = wiki.name
typeof val;
const aClass:ClassA = new ClassA()
typeof new ClassA() //error
typeof aClass;
let person:Person = new Person();
let name =person.name
let name2 =person.getName()
function getPersonInfo(){
    typeof person;
    typeof person.getName();
    typeof name2;
    typeof name;
    typeof person.setAge(111);
    typeof person;
    typeof new Person(); //error
}

const  age = typeof person.setAge(111); 
let person2 = typeof person
class Object {
  code: string = "www"
  location: string = typeof ('123')
  getLocation(){
    console.log(`nameType=${ typeof code} `);
    return typeof this.location;
  }
  setLocation(location: string){
    this.location = location;
    typeof location;
  }
  tips(){
    typeof wiki.name; //error
    typeof age;
    typeof person2;
    typeof fun;
    console.log(`ClassA=${ typeof new ClassA()} `); //error
  }
}

typeof myAaa; //error
typeof new Person().name  //error
typeof new Person().getName() //error
typeof new Person().setAge(22) //error
