-- 007-entities-creation test suite
--
-- Scope:
-- - auth.can_create_* helpers
-- - api.create_* functions (access, group, membership, site, gateway, watcher)
--
-- Expected:
-- - create helpers reflect permissions
-- - API create functions deny without permission
-- - API create functions create rows with proper scoped permission

begin;
select plan(18);

-- ---------------------------------------------------------------------------
-- Fixture setup
-- ---------------------------------------------------------------------------

insert into auth.accesses(name, admin_notes, pass, expires, role, max_session_time, force_change_pass)
values ('t_create_user', null, 'create-pass', null, 'web', 3600, false)
on conflict (name) do nothing;

insert into auth.accesses(name, admin_notes, pass, expires, role, max_session_time, force_change_pass)
values ('t_create_member', null, 'member-pass', null, 'web', 3600, false)
on conflict (name) do nothing;

insert into sites(name, info, perimeter)
values ('t_create_scope_site', null, '((30,30),(30,31),(31,31),(31,30))'::path)
on conflict do nothing;

-- JWT + role
select set_config(
	'request.jwt.claims',
	(
		select json_build_object(
			'id', a.id,
			'verification', '55555555-5555-5555-5555-555555555555'
		)::text
		from auth.accesses a
		where a.name = 't_create_user'
	),
	true
);

set local role web;

-- ---------------------------------------------------------------------------
-- 1) deny paths without create permissions
-- ---------------------------------------------------------------------------

select ok(not auth.can_create_site(), 'can_create_site is false before grant');
select ok(not auth.can_create_access(), 'can_create_access is false before grant');
select ok(not auth.can_create_accesses_group(), 'can_create_accesses_group is false before grant');

select throws_ok(
	$$select api.create_site('t_created_site_fail', '((0,0),(0,1),(1,1),(1,0))'::path, null)$$,
	'42501',
	'missing create(site)',
	'create_site denied without create(site) permission'
);

-- ---------------------------------------------------------------------------
-- 2) grant create permissions to current user
-- ---------------------------------------------------------------------------

set local role postgres;

with acc as (select id from auth.accesses where name = 't_create_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'create', auth.member_bit('all'), 0, 'site' from acc
on conflict do nothing;

with acc as (select id from auth.accesses where name = 't_create_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'create', auth.member_bit('all'), 0, 'access' from acc
on conflict do nothing;

with acc as (select id from auth.accesses where name = 't_create_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'create', auth.member_bit('all'), 0, 'a_group' from acc
on conflict do nothing;

with
	acc as (select id from auth.accesses where name = 't_create_user'),
	site_scope as (select id from sites where name = 't_create_scope_site')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'create', auth.member_bit('all'), site_scope.id, 'gateway'
from acc, site_scope
on conflict do nothing;

set local role web;

select ok(auth.can_create_site(), 'can_create_site true after grant');
select ok(auth.can_create_access(), 'can_create_access true after grant');
select ok(auth.can_create_accesses_group(), 'can_create_accesses_group true after grant');

-- ---------------------------------------------------------------------------
-- 3) create_site + auto-control grant to creator
-- ---------------------------------------------------------------------------

select lives_ok(
	$$select api.create_site('t_created_site', '((40,40),(40,41),(41,41),(41,40))'::path, 'created by test')$$,
	'create_site succeeds with create(site)'
);

select is(
	(
		select count(*)::bigint
		from sites
		where name = 't_created_site'
	),
	1::bigint,
	'create_site inserts site row'
);

-- ---------------------------------------------------------------------------
-- 4) create_access + create_accesses_group + create_access_in_group
-- ---------------------------------------------------------------------------

select lives_ok(
	$$select api.create_access('t_created_access', 'tmp-pass', null, null, 1200, false)$$,
	'create_access succeeds with create(access)'
);

select is(
	(
		select count(*)::bigint
		from auth.accesses
		where name = 't_created_access'
	),
	1::bigint,
	'create_access inserts access row'
);

select lives_ok(
	$$select api.create_accesses_group('t_created_group', 'group from test')$$,
	'create_accesses_group succeeds with create(a_group)'
);

select is(
	(
		select count(*)::bigint
		from accesses_group
		where name = 't_created_group'
	),
	1::bigint,
	'create_accesses_group inserts group row'
);

select lives_ok(
	$$
	select api.create_access_in_group(
		(select id from auth.accesses where name = 't_created_access'),
		(select id from accesses_group where name = 't_created_group')
	)
	$$,
	'create_access_in_group succeeds with create(a_group) scope'
);

select is(
	(
		select count(*)::bigint
		from access_in_group aig
		where
			aig.access = (select id from auth.accesses where name = 't_created_access')
			and aig.a_group = (select id from accesses_group where name = 't_created_group')
	),
	1::bigint,
	'create_access_in_group inserts membership row'
);

-- ---------------------------------------------------------------------------
-- 5) create_gateway + create_watcher scoped flow
-- ---------------------------------------------------------------------------

select lives_ok(
	$$
	select api.create_gateway(
		(select id from sites where name = 't_create_scope_site'),
		't-create-gw-cn',
		't_create_gateway',
		'(30.5,30.5)'::point,
		null
	)
	$$,
	'create_gateway succeeds with create(gateway) on scoped site'
);

set local role postgres;

with
	acc as (select id from auth.accesses where name = 't_create_user'),
	gw as (select id from gateways where cn = 't-create-gw-cn')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'create', auth.member_bit('all'), gw.id, 'watcher'
from acc, gw
on conflict do nothing;

set local role web;

select ok(
	auth.can_create_watcher((select id from gateways where cn = 't-create-gw-cn')),
	'can_create_watcher true after gateway-scoped watcher create grant'
);

select lives_ok(
	$$
	select api.create_watcher(
		(select id from gateways where cn = 't-create-gw-cn'),
		't-create-w-cn',
		't_create_watcher',
		'(30.25,30.25)'::point,
		null
	)
	$$,
	'create_watcher succeeds with create(watcher) on scoped gateway'
);

reset role;
select * from finish();
rollback;
