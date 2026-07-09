select plan(6);

-- minimal fixtures
insert into auth.accesses(name, admin_notes, pass, expires, role, max_session_time, force_change_pass)
values
	('test_web', null, 'pass', null, 'web', null, false),
	('test_other', null, 'pass', null, 'web', null, false)
on conflict (name) do nothing;

insert into accesses_group(name, description)
values ('test_group', 'pgTAP test group')
on conflict (name) do nothing;

insert into access_in_group(access, a_group)
select a.id, g.id
from auth.accesses a
join accesses_group g on g.name = 'test_group'
where a.name = 'test_web'
on conflict do nothing;

with
	acc as (
		select id from auth.accesses where name = 'test_web'
	),
	grp as (
		select id from accesses_group where name = 'test_group'
	)
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select acc.id, 'access', 'read', auth.member_bit('info'), acc.id, 'access' from acc
on conflict do nothing;

with
	grp as (
		select id from accesses_group where name = 'test_group'
	),
	other_acc as (
		select id from auth.accesses where name = 'test_other'
	)
insert into permissions(receiver, receiver_type, action, mask, target, target_type)
select grp.id, 'a_group', 'read', auth.member_bit('location'), other_acc.id, 'access'
from grp, other_acc
on conflict do nothing;

-- claim parsing helpers
select set_config(
	'request.jwt.claims',
	(
		select json_build_object('id', id, 'verification', '11111111-1111-1111-1111-111111111111')::text
		from auth.accesses
		where name = 'test_web'
	),
	true
);

select is(
	auth.jwt_access_id(),
	(select id from auth.accesses where name = 'test_web'),
	'auth.jwt_access_id() reads claim id'
);

select is(
	auth.jwt_verification(),
	'11111111-1111-1111-1111-111111111111'::uuid,
	'auth.jwt_verification() reads claim verification'
);

-- receiver detection
select ok(
	auth.is_permission_receiver('access', (select id from auth.accesses where name = 'test_web')),
	'is_permission_receiver true for direct access receiver'
);

select ok(
	auth.is_permission_receiver('a_group', (select id from accesses_group where name = 'test_group')),
	'is_permission_receiver true for group membership'
);

select ok(
	not auth.is_permission_receiver('access', (select id from auth.accesses where name = 'test_other')),
	'is_permission_receiver false for unrelated access'
);

-- policy-level visibility check on permissions
select is(
	(
		select count(*)
		from permissions p
		where p.action = 'read'
	),
	2::bigint,
	'web claim context can see expected permission rows relevant to receiver/target logic'
);

select * from finish();
