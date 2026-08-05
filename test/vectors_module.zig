// Bridge module so src/ test code can embed test/vectors.json without escaping
// its own package path. The package root of THIS file is test/, where the JSON
// already lives, so @embedFile resolves locally. The bytes are read at compile
// time and exposed as a comptime slice.
pub const json: []const u8 = @embedFile("vectors.json");
