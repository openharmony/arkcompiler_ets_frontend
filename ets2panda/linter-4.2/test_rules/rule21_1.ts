interface ListItem {
    getHead(): ListItem
}

class ListItemImpl implements ListItem {
    n: number = 0

    getHead(): this { return this }
}

