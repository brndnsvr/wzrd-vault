// Package store manages the wzrd-vault SQLite database. It handles schema
// creation and migration, path validation, and CRUD operations on secrets.
// All path validation is centralized here — commands must not validate
// paths independently.
//
// The database uses WAL mode for concurrent read performance and sets a
// 5-second busy timeout to handle concurrent CLI invocations gracefully.
// File permissions are restricted to owner-only (0600) for both the main
// database and WAL/SHM sidecar files.
package store
