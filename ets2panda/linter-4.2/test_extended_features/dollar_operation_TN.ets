//test for defect 14031

export class Foo1 {
  foo1?: string[] = [];
}

@Component
export struct SomeStruct {
  @Link someStruct: Foo1[];
}

export class Foo {
  SomeStruct({
    someStruct: $someStruct
  });
}

