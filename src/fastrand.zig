const std = @import("std");

const Rng = struct {
    seed: u64,

    const Self = @This();

    pub fn init(seed: u64) Self {
        return Self{ .seed = seed };
    }

    pub fn gen_u64(self: *Self) u64 {
        const new_seed = self.seed +% (0xA0761D6478BD642F);
        self.seed = new_seed;
        const value: u128 = @as(u128, @intCast(new_seed)) * @as(u128, @intCast(new_seed ^ 0xE7037ED1A0B428DB));
        return @as(u64, @truncate(value)) ^ @as(u64, @truncate((value >> 64)));
    }

    pub fn gen_u32(self: *Self) u32 {
        return @truncate(self.gen_u64());
    }

    pub fn gen_u8(self: *Self) u8 {
        return @truncate(self.gen_u32());
    }

    pub fn bytes(self: *Self, buf: []u8) void {
        for (0..buf.len) |i| {
            buf[i] = self.gen_u8();
        }
    }
};

test "test fast rand" {
    var rand = Rng.init(0);
    var buf: [16]u8 = undefined;
    rand.bytes(&buf);

    try std.testing.expect(std.mem.eql(
        u8,
        &buf,
        &.{ 142, 109, 164, 96, 222, 31, 41, 162, 87, 10, 126, 142, 58, 197, 26, 153 },
    ));
}
