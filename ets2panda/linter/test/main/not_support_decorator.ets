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

function decorateKlass(target: Object) {
  console.log("decorateKlass")
}

@decorateKlass
class Person {
    age: number = 12
}

function customDecorator(target: Object) {
    console.log("Custom decorator applied");
}

@customDecorator
class User {
    name: string = "John";
    age: number = 30;
}

function decoratorOne(target: Object) {
    console.log("Decorator one applied");
}

function decoratorTwo(target: Object) {
    console.log("Decorator two applied");
}

@decoratorOne
@decoratorTwo
class Product {
    id: number = 1;
    price: number = 9.99;
}

function innerDecorator(target: Object) {
    console.log("Inner decorator applied");
    return target;
}

function outerDecorator(target: Object) {
    return innerDecorator(target);
}

@outerDecorator
class Order {
    orderNumber: string = "12345";
    status: string = "Pending";
}

@outerDecorator()
class Employee {
    employeeId: number = 1001;
    department: string = "HR";
}

@Entry
class EntryTest {
    employeeId: number = 1001;
    department: string = "HR";
}

@Component
class ComponentTest {
    employeeId: number = 1001;
    department: string = "HR";
}

@Sendable
class SendableTest {
    employeeId: number = 1001;
    department: string = "HR";
}

// 1. @ComponentGroup
@ComponentGroup
struct MyComponentGroup {
    build() {
        Column({ space: 50 }) {
            Text('This is a ComponentGroup')
        }
    }
}

// 2. @Controller
@Controller
class MyController {
    someMethod() {
        console.log('Controller method called');
    }
}

// 3. @EntryComponent
@EntryComponent
@Component
struct MyEntryComponent {
    build() {
        Text('This is the entry component')
    }
}

// 4. @Extend
@Component
struct ParentComponent {
    build() {
        Text('Parent Component')
    }
}

@Extend(ParentComponent)
@Component
struct ChildComponent {
    build() {
        super.build();
        Text('Child Component')
    }
}

// 5. @Lazy
@Lazy
@Component
struct LazyComponent {
    build() {
        Text('This is a lazy component')
    }
}

// 6. @Link
@Component
struct Parent {
    private value: string = 'Initial Value';

    build() {
        Column() {
            Text(this.value)
            Child({ value: $value })
        }
    }
}

@Component
struct Child {
    @Link private value: string;

    build() {
        Button('Change Value')
          .onClick(() => {
            })
    }
}

// 7. @LinkParam
@Component
struct Sender {
    private data: string = 'Data from sender';

    build() {
        Column() {
            Receiver({ @LinkParam data: $data })
        }
    }
}

@Component
struct Receiver {
    @LinkParam private data: string;

    build() {
        Text(this.data)
    }
}

// 8. @Module
@Module
class MyModule {
    static someFunction() {
        console.log('Module function called');
    }
}

// 9. @Prop
@Component
struct ParentProp {
    build() {
        ChildProp({ message: 'Hello from parent' })
    }
}

@Component
struct ChildProp {
    @Prop message: string;

    build() {
        Text(this.message)
    }
}

// 10. @Provide 和 @Consume
@Component
struct ProviderTest {
    @Provide private sharedData: string = 'Shared Data';

    build() {
        Column() {
            Consumer()
        }
    }
}

@Component
struct Consumer {
    @Consume private sharedData: string;

    build() {
        Text(this.sharedData)
    }
}

// 11. @Route
@Route({ path: '/home' })
@Component
struct HomePage {
    build() {
        Text('This is the home page')
    }
}

// 12. @RouteParam
@Route({ path: '/user/:id' })
@Component
struct UserPage {
    @RouteParam id: string;

    build() {
        Text(`User ID: ${this.id}`)
    }
}

// 13. @State
@Component
struct Counter {
    @State count: number = 0;

    build() {
        Column() {
            Text(`${this.count}`)
            Button('Increment')
              .onClick(() => {
                })
        }
    }
}

// 14. @StateObject
class MyState {
    @State value: number = 0;
}

@Component
struct StateObjectExample {
    @StateObject private myState = new MyState();

    build() {
        Column() {
            Text(`${this.myState.value}`)
            Button('Increment')
              .onClick(() => {
                })
        }
    }
}

// 15. @Storage
@Component
struct StorageExample {
    @Storage('myKey') private storedValue: string = 'Default Value';

    build() {
        Column() {
            Text(this.storedValue)
            Button('Change Value')
              .onClick(() => {
                })
        }
    }
}

// 16. @StorageLink
@Component
struct StorageProvider {
    @Storage('sharedKey') private sharedValue: string = 'Initial Shared Value';

    build() {
        Column() {
            StorageConsumer()
        }
    }
}

@Component
struct StorageConsumer {
    @StorageLink('sharedKey') private sharedValue: string;

    build() {
    }
}

// 17. @ComponentLink
@Component
struct SourceComponent {
    private componentRef: any;

    build() {
        Column() {
            TargetComponent({ ref: $componentRef })
            Button('Call Target Method')
              .onClick(() => {
                })
        }
    }
}

@Component
struct TargetComponent {
    @ComponentLink ref: any;

    someMethod() {
        console.log('Target component method called');
    }

    build() {
        Text('Target Component')
    }
}

// 18. @ConsumeLink
@Component
struct ProviderLink {
    private sharedValue: string = 'Shared Value via Link';

    build() {
        Column() {
            ConsumerLink({ @ConsumeLink value: $sharedValue })
        }
    }
}

@Component
struct ConsumerLink {
    @ConsumeLink private value: string;

    build() {
        Text(this.value)
    }
}

// 19. @Environment
@Component
struct EnvExample {
    @Environment('color-scheme') private colorScheme: string;

    build() {
    }
}

// 20. @Export
@Export
@Component
struct ExportedComponent {
    build() {
    }
}

// 21. @Name
@Name('CustomName')
@Component
struct NamedComponent {
    build() {
        Text('This is a named component')
    }
}

// 22. @OhosModule
@OhosModule('myModule')
class MyOhosModule {
    static someFunction() {
        console.log('Ohos module function called');
    }
}

// 23. @Builder
@Builder
function MyBuilder() {
}

@Component
struct BuilderExample {
    build() {
        MyBuilder()
    }
}

// 24. @BuilderComponent
@BuilderComponent
struct MyBuilderComponent {
    build() {
        Text('This is a builder component')
    }
}

@Component
struct BuilderCompExample {
    build() {
        MyBuilderComponent()
    }
}

// 25. @PreviewComponent
@PreviewComponent
@Component
struct PreviewComp {
    build() {
    }
}

// 26. @BuilderGroup
@BuilderGroup
function MyBuilderGroup() {
    return Column() {
        Text('Item 1')
        Text('Item 2')
    }
}

@Component
struct BuilderGroupExample {
    build() {
        MyBuilderGroup()
    }
}

// 27. @BuilderParam
@Builder
function MyParamBuilder(@BuilderParam message: string) {
    return Text(message)
}

@Component
struct BuilderParamExample {
    build() {
        MyParamBuilder({ message: 'Message from builder param' })
    }
}

// 28. @PreviewBuilder
@PreviewBuilder
function MyPreviewBuilder() {
}

@Component
struct PreviewBuilderExample {
    build() {
        MyPreviewBuilder()
    }
}

// 29. @PropGroup
@PropGroup
class MyPropGroup {
    title: string = 'Default Title';
    subtitle: string = 'Default Subtitle';
}

@Component
struct PropGroupExample {
    @Prop group: MyPropGroup = new MyPropGroup();

    build() {
        Column() {
        }
    }
}

// 30. @Query
@Route({ path: '/search' })
@Component
struct SearchPage {
    @Query keyword: string;

    build() {
    }
}

// 31. @QueryLink
@Component
struct QuerySender {
    private queryValue: string = 'Query Value';

    build() {
        Column() {
            QueryReceiver({ @QueryLink value: $queryValue })
        }
    }
}

@Component
struct QueryReceiver {
    @QueryLink private value: string;

    build() {
    }
}

// 32. @ScenePhase
@Component
struct ScenePhaseExample {
    @ScenePhase private phase: number;

    build() {
    }
}

// 33. @Suspense
@Suspense
@Component
struct SuspenseExample {
    build() {
        Column() {
            Text('This is inside a suspense component')
        }
    }
}

// 34. @Xml
@Xml(`
    <div>
        <p>XML content</p>
    </div>
`)
@Component
struct XmlExample {
    build() {
        // 这里可以根据需要处理 XML 内容
        Text('XML component')
    }
}
