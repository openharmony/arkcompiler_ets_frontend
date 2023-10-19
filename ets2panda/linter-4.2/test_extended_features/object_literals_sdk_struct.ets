//issue 13689 p3
@Entry
@Component
struct Index {
  build() {
    Row() {
      Test({test:1})
      Test()
    }
    .height('100%')
  }
}
@Component 
struct Test {
  test: number = 1
  build() {}
  
}