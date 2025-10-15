package migration

import "database/sql"

type M20251015InitialSchema struct {
}

func (m *M20251015InitialSchema) Name() string {
	return "20251015_initial_schema"
}

func (m *M20251015InitialSchema) Apply(tx *sql.Tx) error {
	const q = `
-- Site keys.
-- Each key includes a secret key for serverside validation and parameters for creating challenges.
create table site_key
(
    site_key         text    not null
        constraint key_pk
            primary key,
    name             text    not null,
    secret_key       text    not null,
    created_ts       integer not null,
    param_difficulty integer not null,
    param_count      integer not null,
    param_salt_size  integer not null
);

create index key_created_ts_index
    on site_key (created_ts);


	`

	_, err := tx.Exec(q)
	return err
}

func (m *M20251015InitialSchema) Revert(tx *sql.Tx) error {
	const q = `
drop table site_key;
	`

	_, err := tx.Exec(q)
	return err
}
