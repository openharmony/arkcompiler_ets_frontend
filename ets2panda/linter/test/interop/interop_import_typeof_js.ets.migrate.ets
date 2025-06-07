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


let GeneratedImportVar_3 = ESObject.load('./interop_import_js_js');
let wiki = GeneratedImportVar_3.getPropertyByName('Wiki');
let GeneratedImportVar_2 = ESObject.load('./interop_import_js_js');
let Doge = GeneratedImportVar_2.getPropertyByName('Dog');
let GeneratedImportVar_1 = ESObject.load('./interop_import_js_js');
let myAaa = GeneratedImportVar_1.getPropertyByName('aaa');
let ClassA = GeneratedImportVar_1.getPropertyByName('ClassA');
let Dog = GeneratedImportVar_1.getPropertyByName('Dog');
let Person = GeneratedImportVar_1.getPropertyByName('Person');
let Wiki = GeneratedImportVar_1.getPropertyByName('Wiki');


myAaa.invoke().typeOf(); //error
let fun = myAaa();
typeof fun;
Dog.typeOf(); //error
Dog.invoke(ESObject.wrap('doge')).typeOf(); //error
Doge.invoke(ESObject.wrap('doge')).typeOf(); //error
Wiki.typeOf() //error
Wiki.getPropertyByName('name').typeOf() //error
wiki.typeOf() //error
let val = wiki.getPropertyByName("name")
typeof val;
const aClass:ClassA = ClassA.instantiate()
ClassA.instantiate().typeOf() //error
typeof aClass;
let person:Person = Person.instantiate();
let name =person.getPropertyByName("name")
let name2 =person.getName()
function getPersonInfo(){
    typeof person;
    typeof person.getName();
    typeof name2;
    typeof name;
    typeof person.setAge(111);
    typeof person;
    Person.instantiate().typeOf(); //error
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
    wiki.getPropertyByName('name').typeOf(); //error
    typeof age;
    typeof person2;
    typeof fun;
    console.log(`ClassA=${ ClassA.instantiate().typeOf()} `); //error
  }
}

myAaa.typeOf(); //error
Person.instantiate().getPropertyByName('name').typeOf()  //error
Person.instantiate().getPropertyByName('getName').invoke().typeOf() //error
Person.instantiate().getPropertyByName('setAge').invoke(ESObject.wrap(22)).typeOf() //error
