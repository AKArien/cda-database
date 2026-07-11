-- 008-management-write test suite
--
-- Scope:
-- - api.*_rw update triggers and permission enforcement
--
-- Expected:
-- - immutable fields reject updates
-- - mutable fields require matching write mask bits
-- - allowed updates succeed and persist

begin;
select plan(16);

-- ---------------------------------------------------------------------------
-- Fixture setup
-- ---------------------------------------------------------------------------

insert into auth.accesses(name, admin_notes, pass, expires, role, max_session_time, force_change_pass)
values
	('t_write_user', 'note-before', 'write-pass', now() + interval '90 days', 'web', 1000, true)
on conflict (name) do nothing;

insert into sites(name, info, perimeter)
values ('t_write_site', 'site-before', '((50,50),(50,51),(51,51),(51,50))'::path)
on conflict do nothing;

insert into gateways(site, cn, name, info, location)
select s.id, 't-write-gw-cn', 't_write_gateway', 'gw-before', '(50.5,50.5)'::point
from sites s
where s.name = 't_write_site'
on conflict (site, cn) do nothing;

insert into watchers(gateway, cn, name, info, location)
select g.id, 't-write-w-cn', 't_write_watcher', 'w-before', '(50.25,50.25)'::point
from gateways g
where g.cn = 't-write-gw-cn'
on conflict (gateway, cn) do nothing;

insert into accesses_group(name, description)
values ('t_write_group', 'desc-before')
on conflict (name) do nothing;

insert into access_in_group(access, a_group)
select a.id, g.id
from auth.accesses a
join accesses_group g on g.name = 't_write_group'
where a.name = 't_write_user'
on conflict do nothing;

-- JWT + role
select set_config(
	'request.jwt.claims',
	(
		select json_build_object(
			'id', a.id,
			'verification', '66666666-6666-6666-6666-666666666666'
		)::text
		from auth.accesses a
		where a.name = 't_write_user'
	),
	true
);

-- write grants:
-- access: non_sensitive only
with acc as (select id from auth.accesses where name = 't_write_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'write', auth.member_bit('non_sensitive'),
	(select id from auth.accesses where name = 't_write_user'),
	'access'
from acc
on conflict do nothing;

-- site: info only
with acc as (select id from auth.accesses where name = 't_write_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'write', auth.member_bit('info'),
	(select id from sites where name = 't_write_site'),
	'site'
from acc
on conflict do nothing;

-- gateway: location only
with acc as (select id from auth.accesses where name = 't_write_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'write', auth.member_bit('location'),
	(select id from gateways where cn = 't-write-gw-cn'),
	'gateway'
from acc
on conflict do nothing;

-- watcher: info + location
with acc as (select id from auth.accesses where name = 't_write_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'write', auth.member_bit('info') | auth.member_bit('location'),
	(select id from watchers where cn = 't-write-w-cn'),
	'watcher'
from acc
on conflict do nothing;

-- a_group: non_sensitive (for description update)
with acc as (select id from auth.accesses where name = 't_write_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'write', auth.member_bit('non_sensitive'),
	(select id from accesses_group where name = 't_write_group'),
	'a_group'
from acc
on conflict do nothing;

set local role web;

-- ---------------------------------------------------------------------------
-- 1) api.accesses_rw: immutable + writable fields
-- ---------------------------------------------------------------------------

select throws_ok(
	$$
	update api.accesses_rw
	set name = 'renamed'
	where id = (select id from auth.accesses where name = 't_write_user')
	$$,
	'42501',
	'name is immutable',
	'accesses_rw rejects immutable name change'
);

select lives_ok(
	$$
	update api.accesses_rw
	set admin_notes = 'note-after'
	where id = (select id from auth.accesses where name = 't_write_user')
	$$,
	'accesses_rw allows admin_notes with write(non_sensitive)'
);

select throws_ok(
	$$
	update api.accesses_rw
	set expires = now() + interval '120 days'
	where id = (select id from auth.accesses where name = 't_write_user')
	$$,
	'42501',
	'missing write(lifetime) on access',
	'accesses_rw rejects expires change without lifetime bit'
);

-- ---------------------------------------------------------------------------
-- 2) api.sites_rw
-- ---------------------------------------------------------------------------

select lives_ok(
	$$
	update api.sites_rw
	set info = 'site-after'
	where id = (select id from sites where name = 't_write_site')
	$$,
	'sites_rw allows info with write(info)'
);

select throws_ok(
	$$
	update api.sites_rw
	set perimeter = '((0,0),(0,2),(2,2),(2,0))'::path
	where id = (select id from sites where name = 't_write_site')
	$$,
	'42501',
	'missing write(location) on site',
	'sites_rw rejects perimeter without location bit'
);

-- ---------------------------------------------------------------------------
-- 3) api.gateways_rw
-- ---------------------------------------------------------------------------

select lives_ok(
	$$
	update api.gateways_rw
	set location = '(51,51)'::point
	where id = (select id from gateways where cn = 't-write-gw-cn')
	$$,
	'gateways_rw allows location with write(location)'
);

select throws_ok(
	$$
	update api.gateways_rw
	set info = 'gw-after'
	where id = (select id from gateways where cn = 't-write-gw-cn')
	$$,
	'42501',
	'missing write(info) on gateway',
	'gateways_rw rejects info without info bit'
);

-- ---------------------------------------------------------------------------
-- 4) api.watchers_rw
-- ---------------------------------------------------------------------------

select lives_ok(
	$$
	update api.watchers_rw
	set
		info = 'w-after',
		location = '(52,52)'::point
	where id = (select id from watchers where cn = 't-write-w-cn')
	$$,
	'watchers_rw allows info/location with both bits'
);

select throws_ok(
	$$
	update api.watchers_rw
	set name = 'renamed-watcher'
	where id = (select id from watchers where cn = 't-write-w-cn')
	$$,
	'42501',
	'name is immutable',
	'watchers_rw rejects immutable name change'
);

-- ---------------------------------------------------------------------------
-- 5) api.accesses_group_rw + api.access_in_group_rw
-- ---------------------------------------------------------------------------

select lives_ok(
	$$
	update api.accesses_group_rw
	set description = 'desc-after'
	where id = (select id from accesses_group where name = 't_write_group')
	$$,
	'accesses_group_rw allows description with write(non_sensitive)'
);

set local role postgres;

insert into accesses_group(name, description)
values ('t_write_group_target', 'target group')
on conflict (name) do nothing;

with acc as (select id from auth.accesses where name = 't_write_user')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'write', auth.member_bit('non_sensitive'),
	(select id from accesses_group where name = 't_write_group_target'),
	'a_group'
from acc
on conflict do nothing;

set local role web;

select lives_ok(
	$$
	update api.access_in_group_rw
	set a_group = (select id from accesses_group where name = 't_write_group_target')
	where
		access = (select id from auth.accesses where name = 't_write_user')
		and a_group = (select id from accesses_group where name = 't_write_group')
	$$,
	'access_in_group_rw allows reassignment with write(non_sensitive) on source+target groups'
);

-- ---------------------------------------------------------------------------
-- 6) persisted values sanity checks
-- ---------------------------------------------------------------------------

select is(
	(select admin_notes from auth.accesses where name = 't_write_user'),
	'note-after',
	'admin_notes update persisted'
);

select is(
	(select info from sites where name = 't_write_site'),
	'site-after',
	'site info update persisted'
);

select is(
	(select location from gateways where cn = 't-write-gw-cn')::text,
	'(51,51)'::point::text,
	'gateway location update persisted'
);

select is(
	(select description from accesses_group where name = 't_write_group'),
	'desc-after',
	'group description update persisted'
);

select is(
	(
		select count(*)::bigint
		from access_in_group aig
		where
			aig.access = (select id from auth.accesses where name = 't_write_user')
			and aig.a_group = (select id from accesses_group where name = 't_write_group_target')
	),
	1::bigint,
	'access_in_group reassignment persisted'
);

reset role;
select * from finish();
rollback;
