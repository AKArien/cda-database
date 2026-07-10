-- 002-auth test suite
--
-- Scope:
-- - password hashing trigger on auth.accesses
-- - auth.access_get()
-- - api.change_pass()
-- - error_on_no_session()
--
-- Expected:
-- - cleartext passwords are hashed on insert/update
-- - auth.access_get authenticates correctly
-- - change_pass updates password and clears force_change_pass
-- - error_on_no_session raises on invalid/missing session for web role

begin;
select plan(13);

-- ---------------------------------------------------------------------------
-- Fixture setup: dedicated auth test access
-- ---------------------------------------------------------------------------

insert into auth.accesses(name, admin_notes, pass, expires, role, max_session_time, force_change_pass)
values
	('t_auth_user', 'auth test user', 'initial-pass', null, 'web', 3600, true)
on conflict (name) do nothing;

-- ---------------------------------------------------------------------------
-- 1) Password hashing behavior
-- ---------------------------------------------------------------------------

select doesnt_match(
	(select pass from auth.accesses where name = 't_auth_user'),
	'^initial-pass$',
	'insert trigger hashes password (stored value is not cleartext)'
);

select ok(
	(select pass from auth.accesses where name = 't_auth_user') like '$2%',
	'stored password looks like bcrypt hash'
);

update auth.accesses
set pass = 'updated-pass'
where name = 't_auth_user';

select doesnt_match(
	(select pass from auth.accesses where name = 't_auth_user'),
	'^updated-pass$',
	'update trigger hashes new password (not stored as cleartext)'
);

-- ---------------------------------------------------------------------------
-- 2) auth.access_get() behavior
-- ---------------------------------------------------------------------------

select ok(
	auth.access_get('t_auth_user', 'updated-pass') is not null,
	'access_get succeeds with valid credentials'
);

select ok(
	auth.access_get('t_auth_user', 'wrong-pass') is null,
	'access_get returns null on invalid password'
);

select ok(
	auth.access_get('does-not-exist', 'any-pass') is null,
	'access_get returns null on unknown access name'
);

-- ---------------------------------------------------------------------------
-- 3) api.change_pass() behavior
-- ---------------------------------------------------------------------------

select lives_ok(
	$$select api.change_pass('t_auth_user', 'updated-pass', 'final-pass')$$,
	'api.change_pass succeeds with valid old password'
);

select ok(
	auth.access_get('t_auth_user', 'updated-pass') is null,
	'old password no longer works after change_pass'
);

select ok(
	auth.access_get('t_auth_user', 'final-pass') is not null,
	'new password works after change_pass'
);

select is(
	(select force_change_pass from auth.accesses where name = 't_auth_user'),
	false,
	'change_pass clears force_change_pass flag'
);

select throws_ok(
	$$select api.change_pass('t_auth_user', 'bad-old-pass', 'x')$$,
	'28P01',
	null,
	'change_pass fails with invalid old password'
);

-- ---------------------------------------------------------------------------
-- 4) error_on_no_session() behavior
-- ---------------------------------------------------------------------------

-- prepare JWT claims for t_auth_user
select set_config(
	'request.jwt.claims',
	(
		select json_build_object(
			'id', a.id,
			'verification', '22222222-2222-2222-2222-222222222222'
		)::text
		from auth.accesses a
		where a.name = 't_auth_user'
	),
	true
);

-- create valid session row matching claims
insert into auth.sessions(verification, access, expiration)
select
	'22222222-2222-2222-2222-222222222222'::uuid,
	a.id,
	now() + interval '1 hour'
from auth.accesses a
where a.name = 't_auth_user'
on conflict (verification) do update
set
	access = excluded.access,
	expiration = excluded.expiration;

set local role web;

select lives_ok(
	$$select error_on_no_session()$$,
	'error_on_no_session passes when session is valid'
);

-- now break session by changing claim verification
select set_config(
	'request.jwt.claims',
	(
		select json_build_object(
			'id', a.id,
			'verification', '33333333-3333-3333-3333-333333333333'
		)::text
		from auth.accesses a
		where a.name = 't_auth_user'
	),
	true
);

select throws_ok(
	$$select error_on_no_session()$$,
	null,
	'Session invalid or inexistant',
	'error_on_no_session raises when session is missing/invalid'
);

reset role;
select * from finish();
rollback;
