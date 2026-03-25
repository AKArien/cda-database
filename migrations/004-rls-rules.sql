begin;
select _v.register_patch('004-rls-rules', ARRAY['003-permissions-management'], NULL);

-- enable rls
alter table sites enable row level security;
alter table gateways enable row level security;
alter table watchers enable row level security;
alter table auth.accesses enable row level security;
alter table access_in_group enable row level security;
alter table permissions enable row level security;

-- base permissions
grant select on sites to web;
grant select on gateways to web;
grant select on watchers to web;
grant select on auth.accesses to web;
grant select on access_in_group to web;
grant select on permissions to web;

-- no, not the place, find where to later
-- -- account 0 permissions
-- grant all privileges on sites to account_0;
-- grant all privileges on gateways to account_0;
-- grant all privileges on watchers to account_0;
-- grant all privileges on accesses to account_0;
-- grant all privileges on reports to account_0;

-- helpers

create function auth.jwt_access_id() returns int
language sql stable
as $$
	select (current_setting('request.jwt.claims', true)::json->>'id')::int;
$$;

create function auth.jwt_verification() returns uuid
language sql stable
as $$
	select (current_setting('request.jwt.claims', true)::json->>'verification')::uuid;
$$;

create function auth.is_permission_receiver(p_receiver_type permissions_owner, p_receiver int)
returns boolean
language sql
stable
as $$
	select
		(p_receiver_type = 'access' and p_receiver = auth.jwt_access_id())
		or
		(
			p_receiver_type = 'a_group'
			and exists (
				select 1
				from access_in_group aig
				where aig.access = auth.jwt_access_id()
				  and aig.a_group = p_receiver
			)
		);
$$;

grant execute on function auth.jwt_verification() to web;
grant execute on function auth.jwt_access_id() to web;
grant execute on function auth.is_permission_receiver(permissions_owner,int) to web;

-- rls rules

-- read own permissions and permissions over self
create policy own_permissions_read on permissions to web
using (
	( -- user is the receiver
		receiver_type = 'access'
		and receiver = (current_setting('request.jwt.claims', true)::json->>'id')::int
	)
	or
	( -- user is in the receiver group
		receiver_type = 'a_group'
		and exists (
			select 1
			from access_in_group aig
			where
				aig.access = (current_setting('request.jwt.claims', true)::json->>'id')::int
				and aig.a_group = permissions.receiver
		)
	)
	or
	( -- user is the target (only meaningful if target_type='access')
		target_type = 'access'
		and target = (current_setting('request.jwt.claims', true)::json->>'id')::int
	)
	or
	( -- user is in the target group
		target_type = 'a_group'
		and exists (
			select 1
			from access_in_group aig
			where
				aig.access = (current_setting('request.jwt.claims', true)::json->>'id')::int
				and aig.a_group = permissions.target
		)
	)
);

create policy groups_read on access_in_group to web
using (
	access = (current_setting('request.jwt.claims', true)::json->>'id')::int
);


-- on site entities, it’s verbose and repeated, but afaik that’s the best way
-- to do this, as calling each other would re-query and could not be optimised,
-- despite being marked as stable. could be wrong tho ?

create function auth.can_read_site(p_site int)
returns boolean
language sql
stable
as $$
	select exists (
		select p.receiver
		from permissions p
		where p.action = 'read'
		  and p.target_type = 'site'
		  and p.target = p_site
		  and auth.is_permission_receiver(p.receiver_type, p.receiver)
	);
$$;

grant execute on function auth.can_read_site(int) to web;


create function auth.can_read_gateway(p_gateway int, p_site int)
returns boolean
language sql
stable
as $$
	select exists (
		select p.receiver
		from permissions p
		where p.action = 'read'
		  and auth.is_permission_receiver(p.receiver_type, p.receiver)
		  and (
			(p.target_type = 'gateway' and p.target = p_gateway)
			or
			(p.target_type = 'site' and p.target = p_site)
		  )
	);
$$;

grant execute on function auth.can_read_gateway(int,int) to web;


create function auth.can_read_watcher(p_watcher int, p_gateway int, p_site int)
returns boolean
language sql
stable
as $$
	select exists (
		select p.receiver
		from permissions p
		where p.action = 'read'
		  and auth.is_permission_receiver(p.receiver_type, p.receiver)
		  and (
			(p.target_type = 'watcher' and p.target = p_watcher)
			or
			(p.target_type = 'gateway' and p.target = p_gateway)
			or
			(p.target_type = 'site' and p.target = p_site)
		  )
	);
$$;

grant execute on function auth.can_read_watcher(int,int,int) to web;

create policy sites_read on sites
for select to web
using (auth.can_read_site(id));

create policy gateways_read on gateways
for select to web
using (auth.can_read_gateway(id, site));

create policy watchers_read on watchers
for select to web
using (
	auth.can_read_watcher(
		id,
		gateway,
		(select g.site from gateways g where g.id = watchers.gateway)
	)
);


create function auth.can_read_access(p_access int)
returns boolean
language sql
stable
as $$
	select exists (
		select p.receiver
		from permissions p
		where p.action = 'read'
		  and auth.is_permission_receiver(p.receiver_type, p.receiver)
		  and (
			-- direct permissions on this access
			(p.target_type = 'access' and p.target = p_access)
			or
			-- permissions on a group that this access is in
			(
				p.target_type = 'a_group'
				and exists (
					select aig.access
					from access_in_group aig
					where aig.access = p_access
					  and aig.a_group = p.target
				)
			)
		  )
	);
$$;

grant execute on function auth.can_read_access(int) to web;

create policy accesses_read on auth.accesses
for select to web
using (auth.can_read_access(id));

commit;