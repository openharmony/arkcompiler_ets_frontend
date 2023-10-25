    class A {
      public foo: number = 0;
      
      public bar_no_return_def() {
        return this.bar_with_return_def();
      }

      public bar_with_return_def() : number {
        return (2 + 2)
      }
    }

    class B {
      public foo: number = 0;
      
      public bar_no_return_def() {
        return (2 + 2)
      }

      public bar_with_return_def() : number {
        return this.bar_with_return_def();
      }
    }

