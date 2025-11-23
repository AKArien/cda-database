begin;
select _v.register_patch('003-public', ARRAY['002-auth'], NULL);

-- enable rls
alter table job.sites enable row level security;
alter table job.gateways enable row level security;
alter table job.watchers enable row level security;
alter table job.reports enable row level security;

-- rls rules
create policy read_permissions on sites to webuser
for select
using (
	user = current_setting('request.jwt.claims', true)::json->>'id'
);

create view api.sites as
	select * from private.sites
	join auth.sites_permissions
		on private.sites.id = auth.sites_permissions.site
	where auth.sites_permissions.user = current_setting('request.jwt.claims', true)::json->>'id'
;

commit;
