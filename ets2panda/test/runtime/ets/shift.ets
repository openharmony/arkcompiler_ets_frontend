function test_signed_right_shift_int(): void
{
    let tests: int[][] = [
                          [0x7FFFFFFF,   0, 0x7FFFFFFF],
                          [0x7FFFFFFF,  32, 0x7FFFFFFF],
                          [0x7FFFFFFF, -32, 0x7FFFFFFF],
                          [0x7FFFFFFF,   1, 0x3FFFFFFF],
                          [0x7FFFFFFF,  33, 0x3FFFFFFF],
                          [0x7FFFFFFF,  30, 1],
                          [0x7FFFFFFF,  62, 1],
                          [0x7FFFFFFF,  31, 0],
                          [0x7FFFFFFF,  63, 0],
                          [0x7FFFFFFF,  -1, 0],
                          [-1,  0, -1],
                          [-1,  1, -1],
                          [-1, 31, -1],
                          [-4,  0, -4],
                          [-4,  1, -2],
                          [-4, 31, -1],
                         ];

    // runtime tests
    for (let i: int = 0; i<tests.length; i++)
    {
        assert (tests[i][0] >> tests[i][1] == tests[i][2])
    }

    // compile time tests
    assert(0x7FFFFFFF >>   0 == 0x7FFFFFFF);
    assert(0x7FFFFFFF >>  32 == 0x7FFFFFFF);
    assert(0x7FFFFFFF >> -32 == 0x7FFFFFFF);
    assert(0x7FFFFFFF >>   1 == 0x3FFFFFFF);
    assert(0x7FFFFFFF >>  33 == 0x3FFFFFFF);
    assert(0x7FFFFFFF >>  30 == 1);
    assert(0x7FFFFFFF >>  62 == 1);
    assert(0x7FFFFFFF >>  31 == 0);
    assert(0x7FFFFFFF >>  63 == 0);
    assert(0x7FFFFFFF >>  -1 == 0);
    assert(-1 >>  0 == -1);
    assert(-1 >>  1 == -1);
    assert(-1 >> 31 == -1);
    assert(-4 >>  0 == -4);
    assert(-4 >>  1 == -2);
    assert(-4 >> 31 == -1);
}

function test_signed_right_shift_long(): void
{
    let tests: long[][] = [
                          [0x7FFFFFFFFFFFFFFF,    0, 0x7FFFFFFFFFFFFFFF],
                          [0x7FFFFFFFFFFFFFFF,   64, 0x7FFFFFFFFFFFFFFF],
                          [0x7FFFFFFFFFFFFFFF,  -64, 0x7FFFFFFFFFFFFFFF],
                          [0x7FFFFFFFFFFFFFFF,    1, 0x3FFFFFFFFFFFFFFF],
                          [0x7FFFFFFFFFFFFFFF,   65, 0x3FFFFFFFFFFFFFFF],
                          [0x7FFFFFFFFFFFFFFF,   62, 1],
                          [0x7FFFFFFFFFFFFFFF,  126, 1],
                          [0x7FFFFFFFFFFFFFFF,   63, 0],
                          [0x7FFFFFFFFFFFFFFF,  127, 0],
                          [0x7FFFFFFFFFFFFFFF,   -1, 0],
                          [-1,  0, -1],
                          [-1,  1, -1],
                          [-1, 63, -1],
                          [-4,  0, -4],
                          [-4,  1, -2],
                          [-4, 63, -1],
                         ];

    // runtime tests
    for (let i: int = 0; i<tests.length; i++)
    {
        assert (tests[i][0] >> tests[i][1] == tests[i][2])
    }

    // compile time tests
    assert(0x7FFFFFFFFFFFFFFF >>    0 == 0x7FFFFFFFFFFFFFFF);
    assert(0x7FFFFFFFFFFFFFFF >>   64 == 0x7FFFFFFFFFFFFFFF);
    assert(0x7FFFFFFFFFFFFFFF >>  -64 == 0x7FFFFFFFFFFFFFFF);
    assert(0x7FFFFFFFFFFFFFFF >>    1 == 0x3FFFFFFFFFFFFFFF);
    assert(0x7FFFFFFFFFFFFFFF >>   65 == 0x3FFFFFFFFFFFFFFF);
    assert(0x7FFFFFFFFFFFFFFF >>   62 == 1);
    assert(0x7FFFFFFFFFFFFFFF >>  126 == 1);
    assert(0x7FFFFFFFFFFFFFFF >>   63 == 0);
    assert(0x7FFFFFFFFFFFFFFF >>  127 == 0);
    assert(0x7FFFFFFFFFFFFFFF >>   -1 == 0);
    assert(-1 >>  0 == -1);
    assert(-1 >>  1 == -1);
    assert(-1 >> 63 == -1);
    assert(-4 >>  0 == -4);
    assert(-4 >>  1 == -2);
    assert(-4 >> 63 == -1);
}


function main(): void
{
    test_signed_right_shift_int();
    test_signed_right_shift_long();
}
