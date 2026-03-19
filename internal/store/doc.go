// Package store manages the wzrd-vault SQLite database. It handles schema
// creation and migration, path validation, and CRUD operations on secrets.
// All path validation is centralized here — commands must not validate
// paths independently.
package store
