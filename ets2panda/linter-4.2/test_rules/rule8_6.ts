class Foo {
   public fooAttr: unknown;
   public barAttr: number;
   constructor() {
     this.barAttr = 0;
     this.fooAttr = undefined;
   }

  public fooFunc(fooAttr: unknown) {
     let xxxx: unknown;
     console.log(fooAttr)
     console.log(xxxx)
   }
}

class Foo2 {
   protected fooAttr: unknown;
   protected barAttr: number;
   constructor() {
     this.barAttr = 0;
     this.fooAttr = undefined;
   }

  public fooFunc(fooAttr: unknown) {
     let xxxx: unknown;
     console.log(fooAttr)
     console.log(xxxx)
   }
}

class Foo3 {
   private fooAttr: unknown;
   private barAttr: number;
   constructor() {
     this.barAttr = 0;
     this.fooAttr = undefined;
   }

  public fooFunc(fooAttr: unknown) {
     let xxxx: unknown;
     console.log(fooAttr)
     console.log(xxxx)
   }

}

