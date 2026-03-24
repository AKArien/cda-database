begin;
select _v.register_patch('006-api-views', ARRAY['005-column-security'], NULL);

-- views implementing column level security
-- the brains of this is the prior migration

create view api.sites as
select
	s.id,
	s.name,

	auth.mask_text(pm.m, 'info', s.info) as info,
	auth.mask_path(pm.m, 'location', s.perimeter) as perimeter
from sites s
cross join lateral (
	select auth.session_read_mask('site', s.id) as m
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
	select auth.session_read_mask('gateway', g.id) as m
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
	select auth.session_read_mask('watcher', w.id) as m
) pm;

grant select on api.sites to web;
grant select on api.gateways to web;
grant select on api.watchers to web;

commit;