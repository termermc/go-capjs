package main

import (
	"database/sql"
	"fmt"
	"github.com/termermc/go-capjs/standalone/migration"
	"path"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	CapDB        *sql.DB
	StandaloneDB *sql.DB

	incrSolveStmt *sql.Stmt
}

func NewDB(env *Env) (*DB, error) {
	const capFilename = "cap.sqlite?_journal=WAL"
	const standaloneFilename = "standalone.sqlite?_journal=WAL"

	// Open databases.
	capDBPath := path.Join(env.DataPath, capFilename)
	capDB, err := sql.Open("sqlite3", capDBPath)
	if err != nil {
		return nil, fmt.Errorf(`failed to open Cap challenge SQLite DB at "%s": %w`, capDBPath, err)
	}

	standaloneDBPath := path.Join(env.DataPath, standaloneFilename)
	standaloneDB, err := sql.Open("sqlite3", standaloneDBPath)
	if err != nil {
		return nil, fmt.Errorf(`failed to open Cap standalone SQLite DB at "%s": %w`, standaloneDBPath, err)
	}

	// Run migrations.
	err = migration.DoMigrations(standaloneDB)
	if err != nil {
		return nil, fmt.Errorf(`failed to run migations on standalone SQLite DB: %w`, err)
	}

	// Prepare statements.
	incrSolveStmt, err := standaloneDB.Prepare(`
		insert into challenge_solve_count (site_key, unix_hour, count)
		values (?, ?, 1)
		on conflict (site_key, unix_hour)
		do update set count = count + 1
	`)
	if err != nil {
		return nil, fmt.Errorf(`failed to prepare statement: %w`, err)
	}

	return &DB{
		CapDB:        capDB,
		StandaloneDB: standaloneDB,

		incrSolveStmt: incrSolveStmt,
	}, nil
}
