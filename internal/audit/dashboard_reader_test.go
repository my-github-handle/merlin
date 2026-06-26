package audit

// Compile-time assertion: *Reader must satisfy DashboardReader once Task 4 lands.
// Until the methods exist this file fails to compile, which is the failing test.
var _ DashboardReader = (*Reader)(nil)
