begin;
select _v.register_patch('006-api-views', ARRAY['005-column-security'], NULL);

-- views implementing column level security by masking restricted columns
-- the brains of this is the prior migration

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

commit;