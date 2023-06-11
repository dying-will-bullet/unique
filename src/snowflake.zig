const std = @import("std");
const testing = std.testing;
const formatHex = @import("./utils.zig").formatHex;

const BitLenTime = 39;
const BitLenSequence = 8;
const BitLenMachineID = 63 - BitLenTime - BitLenSequence;
const sonyflakeTimeUnit = 10_000_000;
// 2014-09-01T00:00:00 UTC
const DefaultStartTime = 140952960000;

const FlakeID = struct {
    bytes: [8]u8,
    const Self = @This();
    pub fn init() Self {
        return Self{
            .bytes = undefined,
        };
    }
    pub fn formatBuf(self: Self, buf: []u8) error{InvalidSize}!void {
        if (buf.len < 16) {
            return error.InvalidSize;
        }

        return formatHex(buf, self.bytes);
    }
    pub fn asInt(self: Self) u128 {
        return std.mem.readIntBig(u64, &self.bytes);
    }
};

const Options = struct {
    start_time: u64 = 0,
    machind_id: u16,
};

const SnowFlake = struct {
    mutex: std.Thread.Mutex,
    start_time: u64,
    elapsed_time: u64,
    machine_id: u16,
    sequence: u16,

    const Self = @This();

    pub fn init(options: Options) Self {
        var start_time: u64 = DefaultStartTime;

        if (options.start_time != 0) {
            start_time = options.start_time / sonyflakeTimeUnit;
        }

        return Self{
            .mutex = .{},
            .start_time = start_time,
            .elapsed_time = 0,
            .machine_id = options.machind_id,
            .sequence = @intCast(u16, 1 << BitLenSequence - 1),
        };
    }

    pub fn next(self: *Self) !FlakeID {
        const maskSequence = @intCast(u16, 1 << BitLenSequence - 1);
        self.mutex.lock();
        defer self.mutex.unlock();

        var current = @intCast(u64, @divTrunc(std.time.nanoTimestamp(), sonyflakeTimeUnit)) - self.start_time;
        // current = 27701199131;

        if (self.elapsed_time < current) {
            self.elapsed_time = current;
            self.sequence = 0;
        } else {
            self.sequence = (self.sequence + 1) & maskSequence;
            if (self.sequence == 0) {
                self.sequence += 1;
                const overtime = self.elapsed_time - current;
                std.time.sleep(overtime * sonyflakeTimeUnit);
            }
        }

        return self.into();
    }

    pub fn into(self: Self) !FlakeID {
        if (self.elapsed_time >= 1 << BitLenTime) {
            return error.Overflow;
        }
        const i = @intCast(u64, self.elapsed_time) << (BitLenSequence + BitLenMachineID) | @intCast(u64, self.sequence) << BitLenMachineID | @intCast(u64, self.machine_id);
        var id = FlakeID.init();
        std.mem.writeIntBig(u64, &id.bytes, i);
        return id;
    }
};

test "test snowflake" {
    var s = SnowFlake.init(.{ .machind_id = 1 });
    const id = try s.next();
    const id2 = try s.next();

    try testing.expect(id.asInt() != id2.asInt());
}
