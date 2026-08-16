// Vitest has no equivalent of Next's "react-server" resolve condition, which
// is what makes `import "server-only"` a no-op on the server and a build
// error on the client. Without this alias, importing any server-only lib
// module here would hit Next's vendored server-only/index.js, which throws
// unconditionally outside that condition.
export {};
