begin;
select _v.register_patch('007-entities-creation', ARRAY['006-data-ingest'], NULL);

create function auth.can_create_access()
returns boolean
language sql
stable
as $$
	select exists (
		select 1
		from permissions p
		where p.action = 'create'
		  and p.target_type = 'access'
		  and p.target = 0
		  and auth.is_permission_receiver(p.receiver_type, p.receiver)
	);
$$;

create function auth.can_create_site()
returns boolean
language sql
stable
as $$
	select exists (
		select 1
		from permissions p
		where p.action = 'create'
		  and p.target_type = 'site'
		  and p.target = 0
		  and auth.is_permission_receiver(p.receiver_type, p.receiver)
	);
$$;

create function auth.can_create_gateway(p_site int)
returns boolean
language sql
stable
as $$
	select exists (
		select 1
		from permissions p
		where p.action = 'create'
		  and p.target_type = 'gateway'
		  and p.target = p_site
		  and auth.is_permission_receiver(p.receiver_type, p.receiver)
	);
$$;

create function auth.can_create_watcher(p_gateway int)
returns boolean
language sql
stable
as $$
	select exists (
		select 1
		from permissions p
		where p.action = 'create'
		  and p.target_type = 'watcher'
		  and p.target = p_gateway
		  and auth.is_permission_receiver(p.receiver_type, p.receiver)
	);
$$;

grant execute on function auth.can_create_access() to web;
grant execute on function auth.can_create_site() to web;
grant execute on function auth.can_create_gateway(int) to web;
grant execute on function auth.can_create_watcher(int) to web;


create function auth.grant_full_entity_control(
	p_receiver_access int,
	p_target_type permissions_target,
	p_target int
) returns void
language plpgsql
security definer
as $$
begin
	insert into permissions(receiver, receiver_type, action, mask, target, target_type)
	values (p_receiver_access, 'access', 'read', auth.member_bit('all'), p_target, p_target_type)
	on conflict do nothing;

	insert into permissions(receiver, receiver_type, action, mask, target, target_type)
	values (p_receiver_access, 'access', 'manage_reads', 0, p_target, p_target_type)
	on conflict do nothing;

	insert into permissions(receiver, receiver_type, action, mask, target, target_type)
	values (p_receiver_access, 'access', 'manage_manage', 0, p_target, p_target_type)
	on conflict do nothing;
end;
$$;

revoke all on function auth.grant_full_entity_control(int, permissions_target, int) from public;

create function api.create_access(
	p_name text,
	p_pass text,
	p_admin_notes text default null,
	p_expires timestamp default null,
	p_max_session_time int default null,
	p_force_change_pass bool default true
) returns auth.accesses
language plpgsql
security definer
as $$
declare
	v_created auth.accesses%rowtype;
	v_creator int;
begin
	if not auth.can_create_access() then
		raise insufficient_privilege using message = 'missing create(access)';
	end if;

	v_creator := auth.jwt_access_id();

	insert into auth.accesses(name, admin_notes, pass, expires, role, max_session_time, force_change_pass)
	values (p_name, p_admin_notes, p_pass, p_expires, 'web', p_max_session_time, p_force_change_pass)
	returning * into v_created;

	perform auth.grant_full_entity_control(v_creator, 'access', v_created.id);

	return v_created;
end;
$$;

grant execute on function api.create_access(text, text, text, timestamp, int, bool) to web;
grant execute on function api.create_access(text, text, text, timestamp, int, bool) to web;


create function api.create_site(
	p_name text,
	p_perimeter path,
	p_info text default null
) returns sites
language plpgsql
security definer
as $$
declare
	v_created sites%rowtype;
	v_creator int;
begin
	if not auth.can_create_site() then
		raise insufficient_privilege using message = 'missing create(site)';
	end if;

	v_creator := auth.jwt_access_id();

	insert into sites(name, info, perimeter)
	values (p_name, p_info, p_perimeter)
	returning * into v_created;

	perform auth.grant_full_entity_control(v_creator, 'site', v_created.id);

	return v_created;
end;
$$;

grant execute on function api.create_site(text, path, text) to web;


create function api.create_gateway(
	p_site int,
	p_cn text,
	p_name text,
	p_location point,
	p_info text default null
) returns gateways
language plpgsql
security definer
as $$
declare
	v_created gateways%rowtype;
	v_creator int;
begin
	if not auth.can_create_gateway(p_site) then
		raise insufficient_privilege using message = 'missing create(gateway) on site';
	end if;

	v_creator := auth.jwt_access_id();

	insert into gateways(site, cn, name, info, location)
	values (p_site, p_cn, p_name, p_info, p_location)
	returning * into v_created;

	perform auth.grant_full_entity_control(v_creator, 'gateway', v_created.id);

	return v_created;
end;
$$;

grant execute on function api.create_gateway(int, text, text, point, text) to web;


create function api.create_watcher(
	p_gateway int,
	p_cn text,
	p_name text,
	p_location point,
	p_info text default null
) returns watchers
language plpgsql
security definer
as $$
declare
	v_created watchers%rowtype;
	v_creator int;
begin
	if not auth.can_create_watcher(p_gateway) then
		raise insufficient_privilege using message = 'missing create(watcher) on gateway';
	end if;

	v_creator := auth.jwt_access_id();

	insert into watchers(gateway, cn, name, info, location)
	values (p_gateway, p_cn, p_name, p_info, p_location)
	returning * into v_created;

	perform auth.grant_full_entity_control(v_creator, 'watcher', v_created.id);

	return v_created;
end;
$$;

grant execute on function api.create_watcher(int, text, text, point, text) to web;

commit;
