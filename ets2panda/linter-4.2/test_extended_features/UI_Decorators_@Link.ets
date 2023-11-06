/*
* Copyright (c) 2022-2023 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable low or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

class GreenButtonState {
    width: number = 0;

    constructor(width:number) {
        this.width = width;
    }
}

@Component
struct GreenButton {
    @Link greenButtonState: GreenButtonState;

    build() {
        Button("Green Button")
        .width(this.greenButtonState.width)
        .height(150.0)
        .backgroundColor("#00ff00")
        .onClick(() => {
            if (this.greenButtonState.width < 700) {
                this.greenButtonState.width += 125; // update variable's object property, change is observed
            } else {
                this.greenButtonState = new GreenButtonState(100);  // update variable with new class object, change is observed
            }
            console.log("onClick handler on GreenButton, updated value this.greenButtonState.width: " + this.greenButtonState.width);
        })
    }
}

@Component
struct RedButton {
    @State redButtonState: number = 100;

    build() {
        Button("Red Button")
        .width(this.redButtonState)
        .height(150.0)
        .backgroundColor("#ff0000")
        .onClick(() => {
            this.redButtonState = (this.redButtonState < 700) ? this.redButtonState + 80 : 100;
            console.log("onClick handler on RedButton, updated value this.redButtonState: " + this.redButtonState);
        })
    }
}

@Component
struct YellowButton {
    @Prop yellowButtonState: number;

    build(){
        Button("Yellow Button")
        .width(this.yellowButtonState)
        .height(150.0)
        .backgroundColor("#ffff00")
        .onClick(() => {
            this.yellowButtonState += 50.0;
            console.log("onClick handler on YellowButton, updated value this.yellowButtonState: " + this.yellowButtonState);
        })
    }
}

@Entry
@Component
struct ShufflingContainer {
    @State shuffle: boolean = false;
    @State greenButtonState: GreenButtonState = new GreenButtonState(300);
    @State yellowButtonProp: number = 100;

    build() {
        Column(){
           Button(`Parent View: ${this.shuffle ? 'Shuffle to Red before Green' : 'Shuffle to Green before Red'}`)
            .width(700.0)
            .height(150.0)
            .onClick(() => {
                this.shuffle = !this.shuffle;
                console.log("onClick handler on ShufflingContainer, updated value this.shuffle: " + this.shuffle);
            })

            Button("Parent View: Set yellowButtonProp")
            .width(700.0)
            .height(150.0)
            .onClick(() => {
                this.yellowButtonProp = (this.yellowButtonProp < 700) ? this.yellowButtonProp + 100 : 100;
                console.log("onClick handler on ShufflingContainer, updated value of yellowButtonProp: " + this.yellowButtonProp);
            })

            if(this.shuffle) {
                GreenButton({ greenButtonState: this.greenButtonState })
                RedButton()
                YellowButton({ yellowButtonState: this.yellowButtonProp })
            } else {
                RedButton()
                YellowButton({ yellowButtonState: this.yellowButtonProp })
                GreenButton({ greenButtonState: this.greenButtonState })
            }
        }
    }
}
