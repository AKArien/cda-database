begin;
select _v.register_patch('003-rls', ARRAY['002-auth'], NULL);

-- enable rls
alter table sites enable row level security;
alter table gateways enable row level security;
alter table watchers enable row level security;
-- alter table reports enable row level security;

--
grant select on sites to web;
grant select on gateways to web;
grant select on watchers to web;

grant select on auth.sites_permissions to web ;
grant select on auth.gateways_permissions to web;
grant select on auth.watchers_permissions to web;

-- rls rules

-- read data monitoring elements
create policy read_permissions on sites to web
using (
	id = (
		select site from auth.sites_permissions
		where access::text = current_setting('request.jwt.claims', true)::json->>'id'
	)
);

create policy read_permissions on gateways to web
using (
	id = (
		select gateway from auth.gateways_permissions
		where access::text = current_setting('request.jwt.claims', true)::json->>'id'
	)
);

create policy read_permissions on watchers to web
using (
	id = (
		select site from auth.watchers_permissions
		where access::text = current_setting('request.jwt.claims', true)::json->>'id'
	)
);

-- read own permissions
create policy read_own_permissions on auth.sites_permissions to web
using (
	access::text = current_setting('request.jwt.claims', true)::json->>'id'
);

create policy read_own_permissions on auth.gateways_permissions to web
using (
	access::text = current_setting('request.jwt.claims', true)::json->>'id'
);

create policy read_own_permissions on auth.watchers_permissions to web
using (
	access::text = current_setting('request.jwt.claims', true)::json->>'id'
);


commit;
