// https://github.com/ziglang/zig/issues/1316
//

// https://www.mongodb.com/docs/manual/reference/method/ObjectId/
const std = @import("std");
const testing = std.testing;
const formatHex = @import("./utils.zig").formatHex;

const MAX_U24 = 0xff_ffff;

const ObjectId = struct {
    bytes: [12]u8,
    const Self = @This();
    pub fn init() Self {
        return Self{
            .bytes = undefined,
        };
    }
    pub fn formatBuf(self: Self, buf: []u8) error{InvalidSize}!void {
        if (buf.len < 24) {
            return error.InvalidSize;
        }

        return formatHex(buf, &self.bytes);
    }
};

const Generator = struct {
    pid: u32,
    machine_id: u24,
    counter: std.atomic.Atomic(u32),

    const Self = @This();

    pub fn init(machine_id: [3]u8) Self {
        const pid = @intCast(u32, std.os.linux.getpid());
        const start = std.crypto.random.int(u24);

        return Self{
            .pid = pid,
            .machine_id = std.mem.readIntBig(u24, &machine_id),
            .counter = std.atomic.Atomic(u32).init(start),
        };
    }

    pub fn next(self: *Self) ObjectId {
        var obj_id = ObjectId.init();

        const ts = @intCast(u64, std.time.timestamp());
        const seq = self.counter.fetchAdd(1, std.atomic.Ordering.SeqCst) % (MAX_U24 + 1);

        // time-low
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &obj_id.bytes[0]), @truncate(u32, ts));
        // machine id
        std.mem.writeIntBig(u24, @ptrCast(*[3]u8, &obj_id.bytes[4]), self.machine_id);
        // pid
        std.mem.writeIntBig(u16, @ptrCast(*[2]u8, &obj_id.bytes[7]), @truncate(u16, self.pid));
        // counter
        std.mem.writeIntBig(u24, @ptrCast(*[3]u8, &obj_id.bytes[9]), @truncate(u24, seq));

        return obj_id;
    }
};

test "test bson object id" {
    const machine_id = "\x01\x02\x03";

    var generator = Generator.init(machine_id.*);

    const obj_id = generator.next();
    var buf: [24]u8 = undefined;
    try obj_id.formatBuf(&buf);

    const obj_id2 = generator.next();
    var buf2: [24]u8 = undefined;
    try obj_id2.formatBuf(&buf2);

    try std.testing.expect(!std.mem.eql(u8, buf[0..24], buf2[0..24]));
}
