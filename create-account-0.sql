\c cda
\getenv name0 ACCOUNT_ZERO_NAME
\getenv pass0 ACCOUNT_ZERO_PASS

\if :{?name0}
\else
\set name0 'admin'
\endif

\if :{?pass0}
\else
\echo 'ERROR: ACCOUNT_ZERO_PASS is not set'
\quit 1
\endif

do $$
begin
	if not exists (
		select 1
		from information_schema.tables
		where table_schema = 'auth'
		  and table_name = 'accesses'
	) then
		raise exception 'auth.accesses does not exist yet; run this after migrations (at least 002-auth)';
	end if;
end
$$;

insert into auth.accesses (
	name,
	admin_notes,
	pass,
	role,
	force_change_pass
) values (
	:'name0',
	'GENERATED DURING INITIALISATION ACCORDING TO ENVIRONMENT SET',
	:'pass0',
	'account_0'::name,
	false
)
on conflict (name) do nothing;

-- grant absolute root permissions to account_0 access
with root_access as (
	select a.id
	from auth.accesses a
	where a.name = :'name0'
),
all_targets as (
	select unnest(enum_range(null::permissions_target)) as target_type
)
insert into permissions (
	receiver,
	receiver_type,
	action,
	mask,
	target,
	target_type
)
select
	ra.id,
	'access'::permissions_owner,
	v.action,
	case
		when v.action = 'read' then auth.member_bit('all')
		when v.action = 'create' then auth.member_bit('all')
		else 0
	end as mask,
	case
		-- global create scopes
		when v.action = 'create' and t.target_type in ('access','site') then 0

		-- scoped create rows for gateways/watchers are seeded below
		when v.action = 'create' and t.target_type in ('gateway','watcher') then null

		-- non-create permissions target the access itself
		when t.target_type = 'access' then ra.id

		-- skip non-concrete/global-unsupported for bootstrap
		else null
	end as target,
	t.target_type
from root_access ra
cross join all_targets t
cross join (values
	('read'::permissions_verb),
	('manage_reads'::permissions_verb),
	('manage_manage'::permissions_verb),
	('create'::permissions_verb)
) as v(action)
where
	-- keep only valid bootstrap rows
	(
		v.action = 'create'
		and t.target_type in ('access','site')
	)
	or
	(
		v.action in ('read','manage_reads','manage_manage')
		and t.target_type = 'access'
	)
on conflict do nothing;

-- scoped create(gateway) on every existing site
insert into permissions (receiver, receiver_type, action, mask, target, target_type)
select
	ra.id,
	'access'::permissions_owner,
	'create'::permissions_verb,
	auth.member_bit('all'),
	s.id,
	'gateway'::permissions_target
from auth.accesses ra
join sites s on true
where ra.name = :'name0'
on conflict do nothing;

-- scoped create(watcher) on every existing gateway
insert into permissions (receiver, receiver_type, action, mask, target, target_type)
select
	ra.id,
	'access'::permissions_owner,
	'create'::permissions_verb,
	auth.member_bit('all'),
	g.id,
	'watcher'::permissions_target
from auth.accesses ra
join gateways g on true
where ra.name = :'name0'
on conflict do nothing;
