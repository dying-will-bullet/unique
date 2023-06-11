const std = @import("std");

pub fn formatHex(dst: []u8, src: []const u8) error{InvalidSize}!void {
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

pub fn getFileContent(path: []const u8, buf: []u8) ![]const u8 {
    var file = try std.fs.cwd().openFile(path, .{});
    var size = try file.readAll(buf);
    if (size == 0) {
        return error.InvalidSize;
    }

    if (size > 0 and buf[size - 1] == '\n') {
        size -= 1;
    }
    return buf[0..size];
}
