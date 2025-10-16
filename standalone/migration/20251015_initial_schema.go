package migration

import "database/sql"

type M20251015InitialSchema struct {
}

func (m *M20251015InitialSchema) Name() string {
	return "20251015_initial_schema"
}

func (m *M20251015InitialSchema) Apply(tx *sql.Tx) error {
	const q = `
-- Admin sessions.
create table admin_session
(
    id         text                                    not null
        constraint admin_session_pk
            primary key,
    created_ts integer default (strftime('%s', 'now')) not null,
    expires_ts integer                                 not null
);

create index admin_session_created_ts_index
    on admin_session (created_ts);

create index admin_session_expires_ts_index
    on admin_session (expires_ts);

create index admin_session_id_expires_ts_index
    on admin_session (id, expires_ts);

-- Site keys.
-- Each key includes a secret key for serverside validation and parameters for creating challenges.
create table site_key
(
    site_key         text                                    not null
        constraint key_pk
            primary key,
    name             text                                    not null,
    secret_key       text                                    not null,
    created_ts       integer default (strftime('%s', 'now')) not null,
    param_difficulty integer                                 not null,
    param_count      integer                                 not null,
    param_salt_size  integer                                 not null
);

create index key_created_ts_index
    on site_key (created_ts);

-- Challenge solve counts.
-- Includes challenge solve counts per-hour, partitioned by site key.
create table challenge_solve_count
(
    site_key  text    not null,
    unix_hour integer not null,
    count     integer not null,
    constraint challenge_solve_count_pk
        primary key (site_key, unix_hour)
);
	`

	_, err := tx.Exec(q)
	return err
}

func (m *M20251015InitialSchema) Revert(tx *sql.Tx) error {
	const q = `
drop table challenge_solve_count;
drop table site_key;
drop table admin_session;
	`

	_, err := tx.Exec(q)
	return err
}
