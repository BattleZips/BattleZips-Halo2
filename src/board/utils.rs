pub(super) static SHIP_LENGTHS: [usize; 5] = [5, 4, 3, 3, 2];

pub(super) static VALID_SHIPS: [[[u64; 3]; 5]; 4] = [
    [[0, 0, 0], [1, 1, 0], [2, 2, 0], [3, 3, 0], [4, 4, 0]], // basic 1
    [[1, 8, 1], [3, 7, 0], [7, 4, 1], [3, 3, 0], [4, 1, 1]], // basic 2
    [[1, 8, 1], [9, 7, 1], [7, 4, 1], [3, 3, 0], [4, 1, 1]], // ship 2 would fail if z not toggled (ship is vertical)
    [[1, 8, 1], [9, 7, 1], [7, 4, 1], [3, 3, 0], [0, 0, 0]], // ship 5 would fail if z toggled (ship is horizontal)
];

pub(super) static INVALID_SHIPS: [[[u64; 3]; 5]; 6] = [
    [[0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0]], // collision (not working now)
    [[1, 8, 1], [9, 7, 0], [7, 4, 1], [3, 3, 0], [4, 1, 1]], // ship 2 fails as z not toggled (ship is horizontal off board)
    [[1, 8, 1], [9, 7, 1], [7, 4, 1], [3, 3, 0], [0, 0, 1]], // ship 5 fails as z toggled (ship is vertical off board)
    [[1, 8, 1], [10, 7, 1], [7, 4, 1], [3, 3, 0], [0, 0, 0]], // ship 2 x range out of bounds
    [[1, 8, 1], [9, 11, 1], [7, 4, 1], [3, 3, 0], [0, 0, 0]], // ship 2 y range out of bounds
    [[1, 8, 1], [9, 7, 2], [7, 4, 1], [3, 3, 0], [0, 0, 0]], // ship 2 z range out of bounds
];