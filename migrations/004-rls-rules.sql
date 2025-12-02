begin;
select _v.register_patch('004-rls-rules', ARRAY['003-permissions-management'], NULL);

-- enable rls
alter table sites enable row level security;
alter table gateways enable row level security;
alter table watchers enable row level security;
-- alter table reports enable row level security;
alter table permissions enable row level security;

-- base permissions
grant select on sites to web;
grant select on gateways to web;
grant select on watchers to web;
-- grant select on reports to web;
grant select on permissions to web;

-- rls rules

-- read own permissions and permissions over self
create policy own_permissions_read on permissions to web
using (
	( -- user is the reciever
		reciever_type = 'access'
		AND
		reciever = (current_setting('request.jwt.claims', true)::json->>'id')::int
	)
	OR
	( -- user is in a reciever group
		reciever_type = 'a_group'
		AND
		exists (
			select access from access_in_group
			where access = (current_setting('request.jwt.claims', true)::json->>'id')::int
		)
	)
	OR
	( -- user is the target
		target_type = 'access'
		AND
		target = (current_setting('request.jwt.claims', true)::json->>'id')::int
	)
	OR
	( -- user is in a target group
		target_type = 'a_group'
		AND
		exists (
			select access from access_in_group
			where access = (current_setting('request.jwt.claims', true)::json->>'id')::int
		)
	)
);

-- read data monitoring elements
create policy permissions_read on sites to web
using (
	id in (
		select reciever from permissions
		where -- sites where
			target_type = 'site'
			and
			(
				( -- the user has rights
					reciever_type = 'access'
					and
					reciever = (current_setting('request.jwt.claims', true)::json->>'id')::int
				)
				or
				( -- the user is in a group that has rights
					reciever_type = 'a_group'
					and
					exists (
						select access from access_in_group
						where access = (current_setting('request.jwt.claims', true)::json->>'id')::int
					)
				)
			)
	)
);

commit;
