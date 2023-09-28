function main(): void {
  let arr1: Int[] = [1,2,3,4,5];
  let arr2: int[] = [1,2,3,4,5];
  let object_array: Object[] = arr1 as Object[];
  let object: Object = arr1 as Object;

// TypeError: Cannot access property of non-object or non-enum type
// arr1.toString();
// arr2.toString();
// object_array.toString();

  object.toString();

//  TypeError: Cannot access property of non-object or non-enum type
//  arr1.hashCode();
//  arr2.hashCode();
//  object_array.hashCode();

  object.hashCode();

  assert(arr1 == arr1);
  assert(arr1 == object_array);
  assert(arr1 == object);
  assert(arr1 != arr2);
  assert(object.equals(arr1 as Object) == true);

// Cannot cast type 'int[]' to 'Object[]'
//  let object_array2: Object[] = arr2 as Object[];
//  assert(object.equals(arr2 as Object) == false);

  assert(arr2 == arr2);
  assert(arr2 != new int[5]);
}
