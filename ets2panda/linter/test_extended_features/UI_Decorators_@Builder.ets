/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

@Component
struct CreatedByBuilder {

  label : string = "no label";
  @Link link : string;

  build() {
    Text(`CreatedByBuilder ${this.label} ${this.link}`)
      .width(200).height(100)
  }
}

@Builder function ABuilder( $$ : { paramA1: string, paramB1 : string } ) {
  Row() {
    Text(`@UseStateVarByReference: ${$$.paramB1}`)
      .width(200).height(100)

    CreatedByBuilder({ label: $$.paramA1, link: $$.$paramB1 } )
  }
}

@Component
struct LinkChild {

  @Link ls : string;
  private label : string = "LinkChild";

  build() {
    Column() {
      ABuilder({paramA1: this.label, paramB1: this.ls })
    }
    .width(400).height(200)
    .onClick(() => {
      console.log("LinkChild ls changing");
      this.ls = (this.ls == "Hello!") ? "Hej" : "Hello!";
    })
  }
}

@Component
struct PropChild {
  @Prop ps : string;

  build() {
    Column() {
      ABuilder({paramA1: "PropChild", paramB1: this.ps })
    }
    .width(400).height(200)
    .onClick(() => {
      console.log("PropChild ps changing");
      this.ps = (this.ps == "Hello!") ? "Hej" : "Hello!";
    })
  }
}

@Entry
@Component
struct Parent {
  @State s : string = "Hello!";

  build() {
    Column() {
      LinkChild({ls : this.$s})
      Divider().height(10)
      PropChild({ps : this.s})
      Divider().height(10)
      Text(`Parent state'${this.s}'`)
        .width(400).height(50)
    }
  }
}
