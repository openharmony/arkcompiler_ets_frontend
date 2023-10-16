class ListItem1  {
    n: number = 0

    getHead(): this { return this }
}


class ListItem2 extends ListItem1  {
    n: number = 0

    getTail(): this { return this }
}

