    class A {
      public foo: number = 0;
      
      public bar_no_return_def() {
        return 0
      }

      public bar_with_return_def() : number {
        return 0
      }
    }

    function f() {
        let a = new A();
        return a.bar_no_return_def();
    }

    function f2() {
        let a = new A();
        return a.bar_with_return_def();
    }

    function f3():  number{
      let a = new A();
      return a.bar_no_return_def();
    }

    function f2(): number{
      let a = new A();
      return a.bar_with_return_def();
    }
