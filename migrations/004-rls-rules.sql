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

-- read sites
create policy permissions_read on sites to web
using (
	exists (
		select 1
		from permissions p
		where
			p.target_type = 'site'
			and p.target = sites.id
			and p.action = 'read'
			-- optionally constrain to members that map to sites
			and p.member in ('info','location','reports')
			and (
				(
					p.receiver_type = 'access'
					and p.receiver = (current_setting('request.jwt.claims', true)::json->>'id')::int
				)
				or
				(
					p.receiver_type = 'a_group'
					and exists (
						select 1
						from access_in_group aig
						where
							aig.access = (current_setting('request.jwt.claims', true)::json->>'id')::int
							and aig.a_group = p.receiver
					)
				)
			)
	)
);

create policy groups_read on access_in_group to web
using (
	access = (current_setting('request.jwt.claims', true)::json->>'id')::int
);

commit;