begin;
select _v.register_patch('004-rls-rules', ARRAY['003-permissions-management'], NULL);

-- enable rls
alter table sites enable row level security;
alter table gateways enable row level security;
alter table watchers enable row level security;
-- alter table reports enable row level security;
alter table permissions enable row level security;
alter table access_in_group enable row level security;

-- base permissions
grant select on sites to web;
grant select on gateways to web;
grant select on watchers to web;
-- grant select on reports to web;
grant select on permissions to web;
grant select on access_in_group to web;

-- account 0 permissions
grant all privileges on sites to account_0;
grant all privileges on gateways to account_0;
grant all privileges on watchers to account_0;
grant all privileges on reports to account_0;
grant all privileges on permissions to account_0;

-- helper(s)

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

grant execute on function auth.jwt_verification() to web;
grant execute on function auth.jwt_access_id() to web;


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

revoke all on function auth.is_permission_receiver(permissions_owner,int) from public;
grant execute on function auth.is_permission_receiver(permissions_owner,int) to web;

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
	)revoke all on function auth.is_permission_receiver(permissions_owner,int) from public;

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


-- read sites (direct site permissions only)
create policy permissions_read_sites on sites to web
using (
	exists (
		select 1
		from permissions p
		where
			p.target_type = 'site'
			and p.target = sites.id
			and p.action = 'read'
			and auth.is_permission_receiver(p.receiver_type, p.receiver)
	)
);

-- read gateways (gateway permissions OR inherited from site permissions)
create policy permissions_read_watchers on watchers to web
using (
	exists (
		select 1
		from permissions p
		join gateways g on g.id = watchers.gateway
		where
			p.action = 'read'
			and auth.is_permission_receiver(p.receiver_type, p.receiver)
			and (
				(p.target_type = 'gateway' and p.target = watchers.gateway)
				or (p.target_type = 'site' and p.target = g.site)
			)
	)
);

-- read watchers (watcher permissions OR inherited from gateway OR inherited from site)
create policy permissions_read_watchers on watchers to web
using (
	exists (
		select 1
		from permissions p
		join gateways g on g.id = watchers.gateway
		where
			p.action = 'read'
			and auth.is_permission_receiver(p.receiver_type, p.receiver)
			and (
				(p.target_type = 'watcher' and p.target = watchers.id)
				or (p.target_type = 'gateway' and p.target = watchers.gateway)
				or (p.target_type = 'site' and p.target = g.site)
			)
	)
);


commit;