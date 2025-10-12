package migration

import "database/sql"

type M20251010InitialSchema struct {
}

func (m *M20251010InitialSchema) Name() string {
	return "20251010_initial_schema"
}

func (m *M20251010InitialSchema) Apply(tx *sql.Tx) error {
	const q = `
-- Cap challenges.
-- The challenge_token field is the value that clients must compute and will be used to verify solutions.
-- It is also used to look up the challenge and its parameters.
-- The challenge_difficulty, challenge_count and challenge_salt_size fields are the parameters used to on the client to solve the challenge, and on the server to verify solutions.
-- The redeem_token field is the token that will be returned to the client when its solutions are verified.
-- Challenge tokens and redeem tokens must not be accepted if is_redeemed is 1 or expires_ts is in the past.
-- The ip_version and ip_significant_bits fields are used to determine the IP address of the client that generated the challenge.
-- Those fields can be used for rate limiting.
-- After a redeem token is used, is_redeemed is set to 1.
create table cap_challenge (
    challenge_token      text    not null,
    challenge_difficulty integer not null,
    challenge_count      integer not null,
    challenge_salt_size  integer not null,
    redeem_token         text    not null,
    is_redeemed          integer not null,
    ip_version           integer not null,
    ip_significant_bits  integer not null,
    expires_ts           integer not null,
    created_ts           integer default (strftime('%s', 'now')) not null
);

create unique index cap_challenge_challenge_token_uindex
    on cap_challenge (challenge_token);

create index cap_challenge_challenge_token_not_redeemed_index
    on cap_challenge (challenge_token, is_redeemed = 0);

create unique index cap_challenge_redeem_token_uindex
    on cap_challenge (redeem_token);

create unique index cap_challenge_redeem_token_not_redeemed_index
    on cap_challenge (redeem_token, is_redeemed = 0);

create index cap_challenge_is_redeemed_index
    on cap_challenge (is_redeemed);

create index cap_challenge_ip_index
	on cap_challenge (ip_version, ip_significant_bits);

create index cap_challenge_expires_ts_index
    on cap_challenge (expires_ts);

create index cap_challenge_created_ts_index
    on cap_challenge (created_ts);
	`

	_, err := tx.Exec(q)
	return err
}

func (m *M20251010InitialSchema) Revert(tx *sql.Tx) error {
	const q = `
drop table cap_challenge;
	`

	_, err := tx.Exec(q)
	return err
}
