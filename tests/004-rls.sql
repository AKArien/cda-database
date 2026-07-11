-- 004-rls-rules test suite
--
-- Scope:
-- - JWT claim helpers:
--     auth.jwt_access_id()
--     auth.jwt_verification()
-- - Permission receiver resolver:
--     auth.is_permission_receiver(receiver_type, receiver)
-- - RLS policies:
--     permissions (own_permissions_read)
--     access_in_group (groups_read)
-- - Entity read helpers:
--     auth.can_read_site(site)
--     auth.can_read_gateway(gateway)
--     auth.can_read_watcher(watcher)
--
-- Expected:
-- - Claims are parsed correctly from request.jwt.claims
-- - Direct and group receivers are correctly recognized
-- - RLS returns only rows relevant to current access
-- - Read helper functions return true only when matching permissions exist

begin;
select plan(15);

-- ---------------------------------------------------------------------------
-- Fixture setup: minimal topology + actors
-- ---------------------------------------------------------------------------
-- We create:
-- - two accesses: test_web (current JWT user), test_other
-- - one group: test_group, with test_web as member
-- - one site/gateway/watcher chain
-- Expected:
-- - deterministic IDs used by subsequent assertions

insert into auth.accesses(name, admin_notes, pass, expires, role, max_session_time, force_change_pass)
values
	('test_web', null, 'pass', null, 'web', null, false),
	('test_other', null, 'pass', null, 'web', null, false)
on conflict (name) do nothing;

insert into accesses_group(name, description)
values
	('test_group', 'pgTAP group for 004 rls tests'),
	('test_group_other', 'second group to test RLS filtering')
on conflict (name) do nothing;

insert into access_in_group(access, a_group)
select a.id, g.id
from auth.accesses a
join accesses_group g on g.name = 'test_group'
where a.name = 'test_web'
on conflict do nothing;

insert into access_in_group(access, a_group)
select a.id, g.id
from auth.accesses a
join accesses_group g on g.name = 'test_group_other'
where a.name = 'test_other'
on conflict do nothing;

insert into sites(name, info, perimeter)
values ('test_site', 'site info', '((0,0),(0,1),(1,1),(1,0))'::path)
on conflict do nothing;

insert into gateways(site, cn, name, info, location)
select s.id, 'gw-test-01', 'test_gateway', 'gateway info', '(0.5,0.5)'::point
from sites s
where s.name = 'test_site'
on conflict (site, cn) do nothing;

insert into watchers(gateway, cn, name, info, location)
select g.id, 'w-test-01', 'test_watcher', 'watcher info', '(0.25,0.25)'::point
from gateways g
where g.cn = 'gw-test-01'
on conflict (gateway, cn) do nothing;

-- ---------------------------------------------------------------------------
-- Permission fixtures for 004 behavior
-- ---------------------------------------------------------------------------
-- We insert only type-compatible rows:
-- - direct access receiver on access target
-- - group receiver on access target
-- - read permission on site target (for can_read_* helpers)
-- plus unrelated rows to ensure RLS hides them.
--
-- Expected under JWT(test_web):
-- - visible permissions rows = exactly 3 relevant rows
--   (direct receiver, group receiver, target=self)
-- - unrelated rows not visible

with
	web_acc as (select id from auth.accesses where name = 'test_web'),
	other_acc as (select id from auth.accesses where name = 'test_other'),
	web_grp as (select id from accesses_group where name = 'test_group'),
	other_grp as (select id from accesses_group where name = 'test_group_other'),
	site_row as (select id from sites where name = 'test_site')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select web_acc.id, 'access', 'read', auth.member_bit('non_sensitive'), web_acc.id, 'access'
from web_acc
on conflict do nothing;

with
	web_grp as (select id from accesses_group where name = 'test_group'),
	other_acc as (select id from auth.accesses where name = 'test_other')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select web_grp.id, 'a_group', 'read', auth.member_bit('non_sensitive'), other_acc.id, 'access'
from web_grp, other_acc
on conflict do nothing;

with
	web_acc as (select id from auth.accesses where name = 'test_web'),
	site_row as (select id from sites where name = 'test_site')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select web_acc.id, 'access', 'read', auth.member_bit('info') | auth.member_bit('location'), site_row.id, 'site'
from web_acc, site_row
on conflict do nothing;

-- Unrelated row: should not be visible to test_web through own_permissions_read
with
	other_grp as (select id from accesses_group where name = 'test_group_other'),
	site_row as (select id from sites where name = 'test_site')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select other_grp.id, 'a_group', 'read', auth.member_bit('info'), site_row.id, 'site'
from other_grp, site_row
on conflict do nothing;

-- Claim context setup
select set_config(
	'request.jwt.claims',
	(
		select json_build_object(
			'id', a.id,
			'verification', '11111111-1111-1111-1111-111111111111'
		)::text
		from auth.accesses a
		where a.name = 'test_web'
	),
	true
);

-- IMPORTANT:
-- RLS policies in migration 004 are defined "to web".
-- Run assertions under role web so policies are actually evaluated in intended context.
set local role web;

-- 1) JWT helper function checks
select is(
	auth.jwt_access_id(),
	(select id from auth.accesses where name = 'test_web'),
	'jwt_access_id returns current access id from claims'
);

select is(
	auth.jwt_verification(),
	'11111111-1111-1111-1111-111111111111'::uuid,
	'jwt_verification returns UUID from claims'
);

-- 2) Receiver resolution checks
select ok(
	auth.is_permission_receiver(
		'access',
		(select id from auth.accesses where name = 'test_web')
	),
	'is_permission_receiver: true for direct access receiver'
);

select ok(
	auth.is_permission_receiver(
		'a_group',
		(select id from accesses_group where name = 'test_group')
	),
	'is_permission_receiver: true for group membership'
);

select ok(
	not auth.is_permission_receiver(
		'access',
		(select id from auth.accesses where name = 'test_other')
	),
	'is_permission_receiver: false for unrelated access'
);

select ok(
	not auth.is_permission_receiver(
		'a_group',
		(select id from accesses_group where name = 'test_group_other')
	),
	'is_permission_receiver: false for unrelated group'
);

-- 3) RLS policy checks on access_in_group (groups_read)
select is(
	(
		select count(*)::bigint
		from access_in_group
	),
	1::bigint,
	'groups_read policy: only current access memberships are visible'
);

select is(
	(
		select count(*)::bigint
		from access_in_group aig
		where aig.a_group = (select id from accesses_group where name = 'test_group')
	),
	1::bigint,
	'groups_read policy: own group row is visible'
);

select is(
	(
		select count(*)::bigint
		from access_in_group aig
		where aig.a_group = (select id from accesses_group where name = 'test_group_other')
	),
	0::bigint,
	'groups_read policy: unrelated group row is hidden'
);

-- 4) RLS policy checks on permissions (own_permissions_read)
select is(
	(
		select count(*)::bigint
		from permissions p
		where p.action = 'read'
	),
	3::bigint,
	'own_permissions_read policy: only relevant permission rows are visible'
);

select is(
	(
		select count(*)::bigint
		from permissions p
		where
			p.receiver_type = 'a_group'
			and p.receiver = (select id from accesses_group where name = 'test_group_other')
	),
	0::bigint,
	'own_permissions_read policy: unrelated group receiver row is hidden'
);

-- 5) Entity read helper checks from 004
select ok(
	auth.can_read_site((select id from sites where name = 'test_site')),
	'can_read_site: true when read permission exists on site'
);

select ok(
	auth.can_read_gateway((select id from gateways where cn = 'gw-test-01')),
	'can_read_gateway: true when parent site read permission exists'
);

select ok(
	auth.can_read_watcher((select id from watchers where cn = 'w-test-01')),
	'can_read_watcher: true when parent site/gateway read permission exists'
);

select ok(
	not auth.can_read_site(999999),
	'can_read_site: false for unknown site id'
);

reset role;
select * from finish();
rollback;
