type X<T> = T extends number ? T : never

type Y<T> = T extends Array<infer Item> ? Item : never

type X1<T extends number> = T
type X2<T> = Object
type YI<Item, T extends Array<Item>> = Item