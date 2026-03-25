begin;
select _v.register_patch('005-column-security', ARRAY['004-rls-rules'], NULL);

create function auth.read_mask(
	p_target_type permissions_target,
	p_target int
) returns bigint
language sql
stable
security definer
as $$
	-- permissions are stored as masks directly; apply inheritance by OR-ing
	-- masks for the target and its parents.
	with receiver_set as (
		select 'access'::permissions_owner as receiver_type, auth.jwt_access_id() as receiver
		union all
		select 'a_group'::permissions_owner, aig.a_group
		from access_in_group aig
		where aig.access = auth.jwt_access_id()
	),
	target_set as (
		-- direct target always included
		select p_target_type as target_type, p_target as target

		union all
		-- inheritance: gateway implies its site
		select 'site'::permissions_target, g.site
		from gateways g
		where p_target_type = 'gateway' and g.id = p_target

		union all
		-- inheritance: watcher implies its gateway
		select 'gateway'::permissions_target, w.gateway
		from watchers w
		where p_target_type = 'watcher' and w.id = p_target

		union all
		-- inheritance: watcher implies its site (through gateway)
		select 'site'::permissions_target, g.site
		from watchers w
		join gateways g on g.id = w.gateway
		where p_target_type = 'watcher' and w.id = p_target
	)
	select coalesce(bit_or(p.mask), 0::bigint)
	from permissions p
	join receiver_set r
	  on r.receiver_type = p.receiver_type
	 and r.receiver = p.receiver
	join target_set t
	  on t.target_type = p.target_type
	 and t.target = p.target;
	-- where p.action in ('read', 'manage_reads', 'manage_manage');
$$;

grant execute on function auth.read_mask(permissions_target,int) to web;

-- generic "mask one value" helper
-- probably remove this, actually. simpler to have type-specific ones,
-- even though it leads to the truckloads of redundant helpers below.
-- create function auth.mask_value(
-- 	p_mask bigint,
-- 	p_member permissions_member,
-- 	p_value anyelement
-- ) returns anyelement
-- language sql
-- immutable
-- as $$
-- 	select case
-- 		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
-- 		else null
-- 	end;
-- $$;

-- grant execute on function auth.mask_value(bigint,permissions_member,anyelement) to web;
--

create function auth.mask_text(p_mask bigint, p_member permissions_member, p_value text)
returns text
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_text(bigint,permissions_member,text) to web;


create function auth.mask_point(p_mask bigint, p_member permissions_member, p_value point)
returns point
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_point(bigint,permissions_member,point) to web;


create function auth.mask_path(p_mask bigint, p_member permissions_member, p_value path)
returns path
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_path(bigint,permissions_member,path) to web;


create function auth.mask_timestamp(p_mask bigint, p_member permissions_member, p_value timestamp)
returns timestamp
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_timestamp(bigint,permissions_member,timestamp) to web;


create function auth.mask_int(p_mask bigint, p_member permissions_member, p_value int)
returns int
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_int(bigint,permissions_member,int) to web;


create function auth.mask_bool(p_mask bigint, p_member permissions_member, p_value bool)
returns bool
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_bool(bigint,permissions_member,bool) to web;


create function auth.mask_has(p_mask bigint, p_member permissions_member)
returns boolean
language sql immutable
as $$
	select (p_mask & auth.member_bit(p_member)) <> 0;
$$;

grant execute on function auth.mask_has(bigint,permissions_member) to web;


-- views implementing column level security by masking restricted columns
-- what this all has been working up to

create view api.accesses as
select
	a.id,
	auth.mask_text(pm.m, 'non_sensitive', a.name) as name,
	auth.mask_text(pm.m, 'non_sensitive', a.admin_notes) as admin_notes,

	auth.mask_timestamp(pm.m, 'lifetime', a.expires) as expires,
	auth.mask_int(pm.m, 'session_time', a.max_session_time) as max_session_time,
	auth.mask_bool(pm.m, 'change_pass', a.force_change_pass) as force_change_pass
from auth.accesses a
cross join lateral (
	select auth.read_mask('access', a.id) as m
) pm;

grant select on api.accesses to web;


create view api.sites as
select
	s.id,
	s.name,

	auth.mask_text(pm.m, 'info', s.info) as info,
	auth.mask_path(pm.m, 'location', s.perimeter) as perimeter
from sites s
cross join lateral (
	select auth.read_mask('site', s.id) as m
) pm;

create view api.gateways as
select
	g.id,
	g.site,
	g.name,

	auth.mask_text(pm.m, 'info', g.info) as info,
	auth.mask_point(pm.m, 'location', g.location) as location
from gateways g
cross join lateral (
	select auth.read_mask('gateway', g.id) as m
) pm;

create view api.watchers as
select
	w.id,
	w.gateway,
	w.name,

	auth.mask_text(pm.m, 'info', w.info) as info,
	auth.mask_point(pm.m, 'location', w.location) as location
from watchers w
cross join lateral (
	select auth.read_mask('watcher', w.id) as m
) pm;

grant select on api.sites to web;
grant select on api.gateways to web;
grant select on api.watchers to web;

-- reports reader views
-- these are a bit special because we cannot have row level security on them
-- (hypertables with columnstore do not support rls)
-- so we check everything in the views

create view api.reports_watchers as
select
	r.moment,
	r.watcher,
	r.report
from reports r
cross join lateral (
	select auth.read_mask('watcher', r.watcher) as m
) pm
where auth.mask_has(pm.m, 'reports');

grant select on api.reports_watchers to web;


create view api.reports_gateways as
select
	r.moment,
	g.id as gateway,
	sum(r.report)::int as report
from gateways g
cross join lateral (
	select auth.read_mask('gateway', g.id) as m
) pm
join watchers w on w.gateway = g.id
join reports r on r.watcher = w.id
where auth.mask_has(pm.m, 'reports')
group by r.moment, g.id;

grant select on api.reports_gateways to web;


create view api.reports_sites as
select
	r.moment,
	s.id as site,
	sum(r.report)::int as report
from sites s
cross join lateral (
	select auth.read_mask('site', s.id) as m
) pm
join gateways g on g.site = s.id
join watchers w on w.gateway = g.id
join reports r on r.watcher = w.id
where auth.mask_has(pm.m, 'reports')
group by r.moment, s.id;

grant select on api.reports_sites to web;

-- set as security invoker, seems to be security definer as default
alter view api.sites set (security_invoker = true);
alter view api.gateways set (security_invoker = true);
alter view api.watchers set (security_invoker = true);
alter view api.accesses set (security_invoker = true);

commit;