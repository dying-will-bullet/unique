const std = @import("std");
const testing = std.testing;

const UUID_TICKS_BETWEEN_EPOCHS: u64 = 0x01B2_1DD2_1381_4000;

// --------------------------------------------------------------------------------
//                                   timestamp
// --------------------------------------------------------------------------------

pub const Context = struct {
    count: std.atomic.Atomic(u16),

    const Self = @This();

    pub fn fromValue(count: u16) Self {
        return .{ .count = std.atomic.Atomic(u16).init(count) };
    }

    pub fn fromRandom() Self {
        const value = std.crypto.random.int(u16);
        return Self.fromValue(value);
    }

    fn next(self: *Self, seconds: u64, nanos: u32) u16 {
        _ = nanos;
        _ = seconds;
        // RFC4122 reserves 2 bits of the clock sequence so the actual
        // maximum value is smaller than `u16::MAX`. Since we unconditionally
        // increment the clock sequence we want to wrap once it becomes larger
        // than what we can represent in a "u14". Otherwise there'd be patches
        // where the clock sequence doesn't change regardless of the timestamp
        return self.count.fetchAdd(1, std.atomic.Ordering.AcqRel) % (65535 >> 2);
    }
};

pub const Timestamp = struct {
    seconds: u64,
    nanos: u32,
    counter: u16,

    const Self = @This();

    /// Get a timestamp representing the current system time.
    pub fn now(context: anytype) Self {
        const ts = std.time.nanoTimestamp();
        const seconds = @intCast(u64, @divTrunc(ts, 1_000_000_000));
        const nanos = @intCast(u32, @rem(ts, 1_000_000_000));

        return Self{
            .seconds = seconds,
            .nanos = nanos,
            .counter = context.*.next(seconds, nanos),
        };
    }

    /// Construct a `Timestamp` from an RFC4122 timestamp and counter, as used
    /// in versions 1 and 6 UUIDs.
    pub fn fromRFC4122(ticks: u64, counter: u16) Self {
        const seconds = (ticks - UUID_TICKS_BETWEEN_EPOCHS) / 10_000_000;
        const nanos = ((ticks - UUID_TICKS_BETWEEN_EPOCHS) % 10_000_000) * 100;

        return Self{
            .seconds = seconds,
            .nanos = nanos,
            .counter = counter,
        };
    }

    /// Get the value of the timestamp as an RFC4122 timestamp and counter,
    /// as used in versions 1 and 6 UUIDs.
    pub fn toRFC4122(self: Self) std.meta.Tuple(&[_]type{ u64, u16 }) {
        const ticks = UUID_TICKS_BETWEEN_EPOCHS + self.seconds * 10_000_000 + self.nanos / 100;

        return .{ ticks, self.counter };
    }

    /// Construct a `Timestamp` from a Unix timestamp, as used in version 7 UUIDs.
    pub fn fromUnix(context: anytype, seconds: u64, nanos: u32) Self {
        return Self{
            .seconds = seconds,
            .nanos = nanos,
            .counter = context.*.next(seconds, nanos),
        };
    }

    /// Get the value of the timestamp as a Unix timestamp, as used in version 7 UUIDs.
    pub fn toUnix(self: Self) std.meta.Tuple(&[_]type{ u64, u32 }) {
        return .{
            self.seconds,
            self.nanos,
        };
    }
};

const Version = enum(u8) {
    /// The "nil" (all zeros) UUID.
    Nil = 0,
    /// Version 1: Timestamp and node ID.
    Mac = 1,
    /// Version 2: DCE Security.
    Dce = 2,
    /// Version 3: MD5 hash.
    Md5 = 3,
    /// Version 4: Random.
    Random = 4,
    /// Version 5: SHA-1 hash.
    Sha1 = 5,
    /// Version 6: Sortable Timestamp and node ID.
    SortMac = 6,
    /// Version 7: Timestamp and random.
    SortRand = 7,
    /// Version 8: Custom.
    Custom = 8,
    /// The "max" (all ones) UUID.
    Max = 0xff,
};

pub const Namespace = struct {
    /// UUID namespace for Domain Name System (DNS).
    pub const dns = Uuid{ .bytes = .{
        0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    } };

    /// UUID namespace for ISO Object Identifiers (OIDs).
    pub const oid = Uuid{ .bytes = .{
        0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    } };

    /// UUID namespace for Uniform Resource Locators (URLs).
    pub const url = Uuid{ .bytes = .{
        0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    } };

    /// UUID namespace for X.500 Distinguished Names (DNs).
    pub const x500 = Uuid{ .bytes = .{
        0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    } };
};

/// Creates a new UUID from a u128. Performs no validation.
pub fn fromInt(value: u128) Uuid {
    var uuid: Uuid = undefined;
    std.mem.writeIntBig(u128, &uuid.bytes, value);
    return uuid;
}

/// The reserved variants of UUIDs.
///
/// # References
///
/// * [Variant in RFC4122](http://tools.ietf.org/html/rfc4122#section-4.1.1)
/// Msb0  Msb1  Msb2  Description
///  0     x     x    Reserved, NCS backward compatibility.
///  1     0     x    The variant specified in this document.
///  1     1     0    Reserved, Microsoft Corporation backward
///                   compatibility
///  1     1     1    Reserved for future definition.
const Variant = enum(u8) {
    /// Reserved by the NCS for backward compatibility.
    NCS = 0,
    /// As described in the RFC4122 Specification (default).
    RFC4122 = 1,
    /// Reserved by Microsoft for backward compatibility.
    Microsoft = 2,
    /// Reserved for future expansion.
    Future = 3,
};

const Uuid = struct {
    bytes: [16]u8,
    const Self = @This();

    pub fn init() Self {
        return Self{
            .bytes = undefined,
        };
    }

    fn formatHex(dst: []u8, src: []const u8) error{InvalidSize}!void {
        if (dst.len < 2 * src.len) return error.InvalidSize;

        const alphabet = "0123456789abcdef";

        var d: usize = 0;
        var s: usize = 0;
        while (d < dst.len and s < src.len) : ({
            d += 2;
            s += 1;
        }) {
            const byte = src[s];
            dst[d] = alphabet[byte >> 4];
            dst[d + 1] = alphabet[byte & 0xf];
        }
    }

    pub fn formatBuf(self: Self, buf: []u8) error{InvalidSize}!void {
        if (buf.len < 36) return error.InvalidSize;

        formatHex(buf[0..8], self.bytes[0..4]) catch unreachable;
        buf[8] = '-';
        formatHex(buf[9..13], self.bytes[4..6]) catch unreachable;
        buf[13] = '-';
        formatHex(buf[14..18], self.bytes[6..8]) catch unreachable;
        buf[18] = '-';
        formatHex(buf[19..23], self.bytes[8..10]) catch unreachable;
        buf[23] = '-';
        formatHex(buf[24..], self.bytes[10..]) catch unreachable;
    }

    pub fn asInt(self: Self) u128 {
        return std.mem.readIntBig(u128, &self.bytes);
    }
};

const Builder = struct {
    uuid: Uuid,

    const Self = @This();

    pub fn fromRandomBytes() *Self {
        var uuid = Uuid.init();
        std.crypto.random.bytes(&uuid.bytes);
        var self = Self{ .uuid = uuid };

        return self.withVariant(.RFC4122).withVersion(.Random);
    }

    pub fn withVariant(self: *Self, variant: Variant) *Self {
        const byte = self.uuid.bytes[8];

        self.uuid.bytes[8] = switch (variant) {
            .NCS => byte & 0x7f,
            .RFC4122 => (byte & 0x3f) | 0x80,
            .Microsoft => (byte & 0x1f) | 0xc0,
            .Future => byte | 0xe0,
        };

        return self;
    }

    pub fn withVersion(self: *Self, version: Version) *Self {
        self.uuid.bytes[6] = (self.uuid.bytes[6] & 0x0f) | (@enumToInt(version) << 4);
        return self;
    }

    pub fn into(self: Self) Uuid {
        return self.uuid;
    }

    // v7
    pub fn fromUnixTimestampMillis(millis: u64, random_bytes: [10]u8) *Self {
        var uuid = Uuid.init();

        std.mem.writeIntBig(u48, @ptrCast(*[6]u8, &uuid.bytes[0]), @truncate(u48, @bitCast(u64, millis)));

        //TODO:
        // Version includ here
        // uuid.bytes[6] = (random_bytes[1] & 0x0F) | (@enumToInt(Version.SortRand) << 4);
        // uuid.bytes[7] = random_bytes[0];

        // std.mem.copy(u8, uuid.bytes[8..], random_bytes[2..]);

        std.mem.copy(u8, uuid.bytes[6..], random_bytes[0..]);

        var self = Self{ .uuid = uuid };

        return self.withVariant(.RFC4122).withVersion(.SortRand);
    }

    pub fn fromRFC4122Timestamp(ticks: u64, counter: u16, node_id: [6]u8) *Self {
        var uuid = Uuid.init();

        // time-low
        std.mem.writeIntBig(u32, @ptrCast(*[4]u8, &uuid.bytes[0]), @truncate(u32, ticks));
        // time-mid
        std.mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[4]), @truncate(u16, ticks >> 32));
        // time-high
        std.mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[6]), @truncate(u16, ticks >> 48));

        // 14 bits of clock sequence
        std.mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[8]), counter);
        // 48 bits of node ID
        std.mem.copy(u8, uuid.bytes[10..], &node_id);

        var self = Self{ .uuid = uuid };

        return self.withVariant(.RFC4122).withVersion(.Mac);
    }

    pub fn fromSortedRFC4122Timestamp(ticks: u64, counter: u16, node_id: [6]u8) *Self {
        var uuid = Uuid.init();
        // time-high
        std.mem.writeIntBig(u48, @ptrCast(*[6]u8, &uuid.bytes[0]), @truncate(u48, ticks >> 12));
        //TODO: @Hanaasagi
        // time-low and version
        // const version = @intCast(u16, @enumToInt(Version.SortMac));
        // const time_low_and_version = @intCast(u16, (ticks & 0x0FFF)) | (version << 12);
        // std.mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[6]), @truncate(u16, time_low_and_version));

        std.mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[6]), @truncate(u16, ticks & 0xfff));

        // 14 bits of clock sequence
        std.mem.writeIntBig(u16, @ptrCast(*[2]u8, &uuid.bytes[8]), counter);
        // 48 bits of node ID
        std.mem.copy(u8, uuid.bytes[10..], &node_id);

        var self = Self{ .uuid = uuid };

        return self.withVariant(.RFC4122).withVersion(.SortMac);
    }

    pub fn fromMD5Bytes(namespace: Uuid, name: []const u8) *Self {
        var md5 = std.crypto.hash.Md5.init(.{});
        md5.update(&namespace.bytes);
        md5.update(name);

        var uuid = Uuid.init();
        md5.final(&uuid.bytes);
        var self = Self{ .uuid = uuid };

        return self.withVariant(.RFC4122).withVersion(.Md5);
    }

    pub fn fromSHA1Bytes(namespace: Uuid, name: []const u8) *Self {
        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(&namespace.bytes);
        sha1.update(name);

        var uuid = Uuid.init();
        var buf: [20]u8 = undefined;
        sha1.final(&buf);
        std.mem.copy(u8, &uuid.bytes, buf[0..16]);
        var self = Self{ .uuid = uuid };
        return self.withVariant(.RFC4122).withVersion(.Sha1);
    }

    pub fn fromCustomBytes(custom_bytes: []const u8) *Self {
        var uuid = Uuid.init();
        std.mem.copy(u8, &uuid.bytes, custom_bytes[0..16]);

        var self = Self{ .uuid = uuid };
        return self.withVariant(.RFC4122).withVersion(.Custom);
    }
};

// --------------------------------------------------------------------------------
//                                  Public API
// --------------------------------------------------------------------------------

const Node = struct {
    var is_initialized = std.atomic.Atomic(bool).init(false);
    var node_id: [6]u8 = undefined;

    const Self = @This();
    // FIXME:
    fn getNodeId() ![6]u8 {
        if (Node.is_initialized.load(std.atomic.Ordering.SeqCst)) {
            return Node.node_id;
        } else {
            const m = @import("./machine-uid.zig");
            _ = try m.getMachineId(&Node.node_id);
            // TODO: maybe a bug here
            _ = Node.is_initialized.swap(true, std.atomic.Ordering.SeqCst);
        }

        return Node.node_id;
    }
};

pub fn v1() !Uuid {
    var context = Context.fromRandom();
    const ts = Timestamp.now(&context);
    const node_id = try Node.getNodeId();
    return v1WithParam(ts, node_id);
}

pub fn v1WithParam(ts: Timestamp, node_id: [6]u8) Uuid {
    const tuple = ts.toRFC4122();
    const ticks = tuple[0];
    const counter = tuple[1];

    var uuid = Builder.fromRFC4122Timestamp(ticks, counter, node_id).into();

    return uuid;
}

pub fn v3(namespace: Uuid, name: []const u8) Uuid {
    var uuid = Builder.fromMD5Bytes(namespace, name).into();

    return uuid;
}

pub fn v4() Uuid {
    var uuid = Builder.fromRandomBytes().into();

    return uuid;
}

pub fn v5(namespace: Uuid, name: []const u8) Uuid {
    var uuid = Builder.fromSHA1Bytes(namespace, name).into();

    return uuid;
}

pub fn v6() !Uuid {
    var context = Context.fromRandom();
    const ts = Timestamp.now(&context);
    const node_id = try Node.getNodeId();
    return v6WithParam(ts, node_id);
}

pub fn v6WithParam(ts: Timestamp, node_id: [6]u8) Uuid {
    const tuple = ts.toRFC4122();
    const ticks = tuple[0];
    const counter = tuple[1];
    var uuid = Builder.fromSortedRFC4122Timestamp(ticks, counter, node_id).into();

    return uuid;
}

pub fn v7() Uuid {
    var context = Context.fromValue(0);
    const ts = Timestamp.now(&context);

    return v7WithParam(ts);
}

pub fn v7WithParam(ts: Timestamp) Uuid {
    const tuple = ts.toUnix();
    const seconds = tuple[0];
    const nanos = tuple[1];
    const millis = seconds * 1000 + (@intCast(u64, nanos) / 1_000_000);

    var bytes: [10]u8 = undefined;
    std.crypto.random.bytes(bytes[0..]);
    var uuid = Builder.fromUnixTimestampMillis(millis, bytes).into();
    return uuid;
}

pub fn v8(custom_bytes: []const u8) Uuid {
    var uuid = Builder.fromCustomBytes(custom_bytes).into();

    return uuid;
}

// --------------------------------------------------------------------------------
//                                   Testing
// --------------------------------------------------------------------------------

test "test v1" {
    const uuid = try v1();
    const uuid2 = try v1();

    // var buf: [36]u8 = undefined;
    // try uuid.formatBuf(&buf);
    // std.debug.print("\r\n{s}\r\n", .{buf});
    // try uuid2.formatBuf(&buf);
    // std.debug.print("\r\n{s}\r\n", .{buf});

    try testing.expect(!std.mem.eql(u8, &uuid.bytes, &uuid2.bytes));
    // node id should be same
    try testing.expect(std.mem.eql(u8, uuid.bytes[10..], uuid2.bytes[10..]));
}

test "test v1WithParam" {
    const time: u64 = 1_496_854_535;
    const time_fraction: u32 = 812_946_000;
    const node_id: [6]u8 = .{ 1, 2, 3, 4, 5, 6 };
    var context = Context.fromValue(0);

    const uuid = v1WithParam(Timestamp.fromUnix(&context, time, time_fraction), node_id);
    var buf: [36]u8 = undefined;
    try uuid.formatBuf(&buf);
    try testing.expectEqualStrings("20616934-4ba2-11e7-8000-010203040506", &buf);
}

test "test v3" {
    var uuid = v3(Namespace.dns, "example.org");

    var buf: [36]u8 = undefined;
    try uuid.formatBuf(&buf);
    try testing.expectEqualStrings("04738bdf-b25a-3829-a801-b21a1d25095b", &buf);
}

test "test v4" {
    const allocator = testing.allocator;
    var uuid = v4();
    var uuid2 = v4();
    var uuid3 = v4();

    var buf: [36]u8 = undefined;
    try uuid.formatBuf(&buf);
    const s1 = try allocator.dupe(u8, &buf);
    defer allocator.free(s1);

    try uuid2.formatBuf(&buf);
    const s2 = try allocator.dupe(u8, &buf);
    defer allocator.free(s2);

    try uuid3.formatBuf(&buf);
    const s3 = try allocator.dupe(u8, &buf);
    defer allocator.free(s3);

    try testing.expect(!std.mem.eql(u8, s1, s2));
    try testing.expect(!std.mem.eql(u8, s2, s3));
    try testing.expect(!std.mem.eql(u8, s3, s1));
}

test "test v5" {
    var uuid = v5(Namespace.dns, "example.org");

    var buf: [36]u8 = undefined;
    try uuid.formatBuf(&buf);
    try testing.expectEqualStrings("aad03681-8b63-5304-89e0-8ca8f49461b5", &buf);
}

test "test v6" {
    const uuid = try v6();
    const uuid2 = try v6();

    try testing.expect(!std.mem.eql(u8, &uuid.bytes, &uuid2.bytes));
    // node id should be same
    try testing.expect(std.mem.eql(u8, uuid.bytes[10..], uuid2.bytes[10..]));
}

test "test v6WithParam" {
    const time: u64 = 1_496_854_535;
    const time_fraction: u32 = 812_946_000;
    const node_id: [6]u8 = .{ 1, 2, 3, 4, 5, 6 };
    var context = Context.fromValue(0);

    const uuid = v6WithParam(Timestamp.fromUnix(&context, time, time_fraction), node_id);
    var buf: [36]u8 = undefined;
    try uuid.formatBuf(&buf);
    try testing.expectEqualStrings("1e74ba22-0616-6934-8000-010203040506", &buf);
}

test "test v7" {
    const uuid = v7();
    const uuid2 = v7();

    try testing.expect(!std.mem.eql(u8, &uuid.bytes, &uuid2.bytes));
}

test "test v7WithParam" {
    const seconds: u64 = 1_496_854_535;
    const nanos: u32 = 812_946_000;
    const millis = seconds * 1000 + (@intCast(u64, nanos) / 1_000_000);
    var bytes: [10]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

    const uuid = Builder.fromUnixTimestampMillis(millis, bytes).into();
    var buf: [36]u8 = undefined;
    try uuid.formatBuf(&buf);
    try testing.expectEqualStrings("015c837b-9e84-7102-8304-05060708090a", &buf);
}

test "test v8" {
    var uuid = v8(&.{
        0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    });
    var buf: [36]u8 = undefined;
    try uuid.formatBuf(&buf);
    try testing.expectEqualStrings("0f0e0d0c-0b0a-8908-8706-050403020100", &buf);
}

test "test asInt" {
    var uuid = v8(&.{
        0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
    });
    const i: u128 = uuid.asInt();
    try testing.expect(i == 20011376718273094810986612628167721216);
}
