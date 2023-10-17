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

@Entry
@Component
struct Basket {

    @State @Watch("onBasketUpdated") shopBasket : Array<number>= [ 7, 12, 47, 3 ];
    @State totalPurchase : number = this.updateTotal();

    updateTotal() : number {
        let total = this.shopBasket.reduce((sum, i) =>  sum + i , 0);

        // Apply discount if over 100EUR
        if (total >= 100) {
            total = 0.9 * total;
        }
        return total;
    }
    
    // @Watch cb
    onBasketUpdated(propName: string) : void {
        this.totalPurchase = this.updateTotal();
    }

    build() {
        Column() {
            Text(`Total: ${this.totalPurchase.toFixed(2)} €`)

            Button("Add to basket")
            .onClick(() => { 
                this.shopBasket.push(Math.round(100 * Math.random()));
            })
        }
    }
}
