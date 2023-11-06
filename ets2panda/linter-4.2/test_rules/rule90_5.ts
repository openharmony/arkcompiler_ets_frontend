class Data1 {
   public foo: number = 0;
}

class Data2 extends Data1{
   public foo: number = 0;

}


function dataFactory1() : Data1 {
  return new Data2();
} 

function dataFactory2() : Data2 {
  return new Data1();
}
