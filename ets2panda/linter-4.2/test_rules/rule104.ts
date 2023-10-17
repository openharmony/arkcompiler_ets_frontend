class Control {
    state: number = 0
}

interface SelectableControl extends Control {
    select(): void
}