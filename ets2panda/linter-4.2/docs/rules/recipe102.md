#  Interface can not extend interfaces with the same method

Rule ``arkts-no-extend-same-prop``

**Severity: error**

In TypeScript, an interface that extends two other interfaces with the same method
must declare that method with a combined result type. It is not allowed in
ArkTS because ArkTS does not allow an interface to contain two methods with
signatures that are  not distinguishable, e.g., two methods that have the same
parameter lists but different return types.


## TypeScript


```

    interface Mover {
        getStatus(): { speed: number }
    }
    interface Shaker {
        getStatus(): { frequency: number }
    }

    interface MoverShaker extends Mover, Shaker {
        getStatus(): {
            speed: number
            frequency: number
        }
    }

    class C implements MoverShaker {
        private speed: number = 0
        private frequency: number = 0

        getStatus() {
            return { speed: this.speed, frequency: this.frequency }
        }
    }

```

## ArkTS


```

    class MoveStatus {
        public speed : number
        constructor() {
            this.speed = 0
        }
    }
    interface Mover {
        getMoveStatus(): MoveStatus
    }

    class ShakeStatus {
        public frequency : number
        constructor() {
            this.frequency = 0
        }
    }
    interface Shaker {
        getShakeStatus(): ShakeStatus
    }

    class MoveAndShakeStatus {
        public speed : number
        public frequency : number
        constructor() {
            this.speed = 0
            this.frequency = 0
        }
    }

    class C implements Mover, Shaker {
        private move_status : MoveStatus
        private shake_status : ShakeStatus

        constructor() {
            this.move_status = new MoveStatus()
            this.shake_status = new ShakeStatus()
        }

        public getMoveStatus() : MoveStatus {
            return this.move_status
        }

        public getShakeStatus() : ShakeStatus {
            return this.shake_status
        }

        public getStatus(): MoveAndShakeStatus {
            return {
                speed: this.move_status.speed,
                frequency: this.shake_status.frequency
            }
        }
    }

```


