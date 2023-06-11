const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const formatHex = @import("./utils.zig").formatHex;
const getFileContent = @import("./utils.zig").getFileContent;

// Platform: linux
// The contents of the following two files should be the same.
const DBUS_PATH = "/var/lib/dbus/machine-id";
const DBUS_FALLBACK_PATH = "/etc/machine-id";

// Platform: any container
const HOSTNAME_PATH = "/etc/hostname";

// Platform: BSD
const HOSTID_PATH = "/etc/hostid";

/// Sha256 of /etc/hostname
fn hostnameHash(buf: []u8) ![]const u8 {
    var tmp: [32]u8 = undefined;
    var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
    const hostname = try getFileContent(HOSTNAME_PATH, buf);
    sha256.update(hostname);
    sha256.final(&tmp);

    try formatHex(buf, &tmp);

    return buf[0..32];
}

pub fn getMachineId(buf: []u8) ![]const u8 {
    switch (builtin.os.tag) {
        .linux => {
            return getFileContent(DBUS_PATH, buf) catch {
                return getFileContent(DBUS_FALLBACK_PATH, buf) catch {
                    return try hostnameHash(buf);
                };
            };
        },
        .freebsd, .openbsd, .netbsd, .dragonfly => {
            // TODO: kenv
            return try getFileContent(HOSTID_PATH, buf) catch {
                return try hostnameHash(buf);
            };
        },
        else => {
            // TODO: mac and windows
            @compileError("unsupported os");
        },
    }
}

test "test hostname hash" {
    var buf: [64]u8 = undefined;
    _ = try hostnameHash(&buf);
}

test "test get machine id" {
    var buf: [64]u8 = undefined;
    _ = try getMachineId(&buf);
}
