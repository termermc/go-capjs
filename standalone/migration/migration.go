package migration

import (
	"database/sql"
	"slices"
)

// Migration represents a database migration.
type Migration interface {
	// Name returns the name of the migration.
	Name() string

	// Apply applies the migration to the database.
	Apply(tx *sql.Tx) error

	// Revert reverts the migration from the database.
	Revert(tx *sql.Tx) error
}

var migrations = []Migration{
	&M20251015InitialSchema{},
}

// DoMigrations applies all migrations to the database.
func DoMigrations(db *sql.DB) error {
	// Create table if it doesn't exist.
	_, err := db.Exec(`
		create table if not exists migration (
			name text not null primary key,
			created_ts integer not null default (strftime('%s', 'now'))
		)
	`)
	if err != nil {
		return err
	}

	// Get the names of already-applied migrations.
	var appliedNames []string
	rows, err := db.Query(`select name from migration`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		err = rows.Scan(&name)
		if err != nil {
			_ = rows.Close()
			return err
		}

		appliedNames = append(appliedNames, name)
	}
	_ = rows.Close()

	for _, m := range migrations {
		if slices.Contains(appliedNames, m.Name()) {
			continue
		}

		var tx *sql.Tx
		tx, err = db.Begin()
		if err != nil {
			return err
		}

		err = m.Apply(tx)
		if err != nil {
			_ = tx.Rollback()
			return err
		}

		_, err = tx.Exec(`insert into migration (name) values (?)`, m.Name())
		if err != nil {
			_ = tx.Rollback()
			return err
		}

		err = tx.Commit()
		if err != nil {
			return err
		}
	}

	return nil
}
