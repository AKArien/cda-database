-- 005-column-security test suite
--
-- Scope:
-- - auth.permission_mask(), auth.read_mask(), auth.write_mask()
-- - mask helpers (mask_text, mask_point, mask_path, mask_timestamp, mask_int, mask_bool, mask_has)
-- - api masked views (api.accesses, api.sites, api.gateways, api.watchers)
--
-- Expected:
-- - permission masks aggregate direct + inherited permissions correctly
-- - helper masking functions reveal/hide values based on bit membership
-- - api views expose only allowed columns

begin;
select plan(17);

-- ---------------------------------------------------------------------------
-- Fixture setup
-- ---------------------------------------------------------------------------

insert into auth.accesses(name, admin_notes, pass, expires, role, max_session_time, force_change_pass)
values
	('t_mask_user', 'sensitive-note', 'mask-pass', now() + interval '30 days', 'web', 1800, true)
on conflict (name) do nothing;

insert into sites(name, info, perimeter)
values ('t_mask_site', 'secret-site-info', '((10,10),(10,11),(11,11),(11,10))'::path)
on conflict do nothing;

insert into gateways(site, cn, name, info, location)
select s.id, 't-mask-gw-cn', 't_mask_gateway', 'secret-gw-info', '(10.5,10.5)'::point
from sites s
where s.name = 't_mask_site'
on conflict (site, cn) do nothing;

insert into watchers(gateway, cn, name, info, location)
select g.id, 't-mask-w-cn', 't_mask_watcher', 'secret-w-info', '(10.25,10.25)'::point
from gateways g
where g.cn = 't-mask-gw-cn'
on conflict (gateway, cn) do nothing;

-- Permissions:
-- - read on own access: only non_sensitive
-- - read on site: info only (no location)
-- - write on site: location only (for write_mask sanity)
with
	acc as (select id from auth.accesses where name = 't_mask_user'),
	site_row as (select id from sites where name = 't_mask_site')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'read', auth.member_bit('non_sensitive'), acc.id, 'access'
from acc
on conflict do nothing;

with
	acc as (select id from auth.accesses where name = 't_mask_user'),
	site_row as (select id from sites where name = 't_mask_site')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'read', auth.member_bit('info'), site_row.id, 'site'
from acc, site_row
on conflict do nothing;

with
	acc as (select id from auth.accesses where name = 't_mask_user'),
	site_row as (select id from sites where name = 't_mask_site')
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'write', auth.member_bit('location'), site_row.id, 'site'
from acc, site_row
on conflict do nothing;

-- JWT + role context
select set_config(
	'request.jwt.claims',
	(
		select json_build_object(
			'id', a.id,
			'verification', '44444444-4444-4444-4444-444444444444'
		)::text
		from auth.accesses a
		where a.name = 't_mask_user'
	),
	true
);

set local role web;

-- ---------------------------------------------------------------------------
-- 1) permission_mask / read_mask / write_mask
-- ---------------------------------------------------------------------------

select is(
	auth.read_mask('access', (select id from auth.accesses where name = 't_mask_user')),
	auth.member_bit('non_sensitive'),
	'read_mask(access) returns configured access mask'
);

select is(
	auth.read_mask('site', (select id from sites where name = 't_mask_site')),
	auth.member_bit('info'),
	'read_mask(site) returns configured site read mask'
);

select is(
	auth.write_mask('site', (select id from sites where name = 't_mask_site')),
	auth.member_bit('location'),
	'write_mask(site) returns configured site write mask'
);

-- gateway / watcher inherit from site in permission_mask target_set
select is(
	auth.read_mask('gateway', (select id from gateways where cn = 't-mask-gw-cn')),
	auth.member_bit('info'),
	'read_mask(gateway) inherits site read permission'
);

select is(
	auth.read_mask('watcher', (select id from watchers where cn = 't-mask-w-cn')),
	auth.member_bit('info'),
	'read_mask(watcher) inherits site read permission'
);

-- ---------------------------------------------------------------------------
-- 2) mask helper functions
-- ---------------------------------------------------------------------------

select is(
	auth.mask_text(auth.member_bit('info'), 'info', 'abc'),
	'abc',
	'mask_text returns value when bit is present'
);

select is(
	auth.mask_text(0::bigint, 'info', 'abc'),
	null::text,
	'mask_text returns null when bit is absent'
);

-- geometric types don’t have an equality operator, so compare them as text
select is(
    auth.mask_point(auth.member_bit('location'), 'location', '(1,2)'::point)::text,
    '(1,2)'::point::text,
    'mask_point returns point when bit is present'
);

select is(
	auth.mask_path(0::bigint, 'location', '((0,0),(1,1))'::path)::text,
	null::path::text,
	'mask_path returns null when bit is absent'
);

select is(
	auth.mask_int(auth.member_bit('reports'), 'reports', 12),
	12,
	'mask_int returns int when bit is present'
);

select is(
	auth.mask_bool(0::bigint, 'change_pass', true),
	null::boolean,
	'mask_bool returns null when bit is absent'
);

select ok(
	auth.mask_has(auth.member_bit('info') | auth.member_bit('location'), 'location'),
	'mask_has returns true when member bit is set'
);

select ok(
	not auth.mask_has(auth.member_bit('info'), 'reports'),
	'mask_has returns false when member bit is not set'
);

-- ---------------------------------------------------------------------------
-- 3) masked API views behavior
-- ---------------------------------------------------------------------------

select is(
	(
		select a.name
		from api.accesses a
		where a.id = (select id from auth.accesses where name = 't_mask_user')
	),
	't_mask_user',
	'api.accesses exposes non_sensitive field name when allowed'
);

select is(
	(
		select a.expires
		from api.accesses a
		where a.id = (select id from auth.accesses where name = 't_mask_user')
	),
	null::timestamp,
	'api.accesses masks lifetime field when not allowed'
);

select is(
	(
		select s.info
		from api.sites s
		where s.id = (select id from sites where name = 't_mask_site')
	),
	'secret-site-info',
	'api.sites exposes info when info bit is granted'
);

select is(
	(
		select s.perimeter
		from api.sites s
		where s.id = (select id from sites where name = 't_mask_site')
	),
	null::path,
	'api.sites masks location/perimeter when location bit is not granted'
);

reset role;
select * from finish();
rollback;
