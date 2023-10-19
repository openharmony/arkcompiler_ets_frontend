//issue 13689 p4
@Entry
@Component
struct Index {
  private testcase;
  build() {
    Row() {

    }
    .height('100%')
    .onClick(()=>{
      this.testcase({
        a:1,
        b:2,
      });
    })
  }
}

@Component 
struct Test {
  test: number = 1
  build() {}
  
}