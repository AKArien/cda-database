begin;
select _v.register_patch('005-column-security', ARRAY['004-rls-rules'], NULL);

create function auth.read_mask(
	p_target_type permissions_target,
	p_target int
) returns bigint
language sql
stable
security definer
as $$
	-- permissions are stored as masks directly; apply inheritance by OR-ing
	-- masks for the target and its parents.
	with receiver_set as (
		select 'access'::permissions_owner as receiver_type, auth.jwt_access_id() as receiver
		union all
		select 'a_group'::permissions_owner, aig.a_group
		from access_in_group aig
		where aig.access = auth.jwt_access_id()
	),
	target_set as (
		-- direct target always included
		select p_target_type as target_type, p_target as target

		union all
		-- inheritance: gateway implies its site
		select 'site'::permissions_target, g.site
		from gateways g
		where p_target_type = 'gateway' and g.id = p_target

		union all
		-- inheritance: watcher implies its gateway
		select 'gateway'::permissions_target, w.gateway
		from watchers w
		where p_target_type = 'watcher' and w.id = p_target

		union all
		-- inheritance: watcher implies its site (through gateway)
		select 'site'::permissions_target, g.site
		from watchers w
		join gateways g on g.id = w.gateway
		where p_target_type = 'watcher' and w.id = p_target
	)
	select coalesce(bit_or(p.mask), 0::bigint)
	from permissions p
	join receiver_set r
	  on r.receiver_type = p.receiver_type
	 and r.receiver = p.receiver
	join target_set t
	  on t.target_type = p.target_type
	 and t.target = p.target;
	-- where p.action in ('read', 'manage_reads', 'manage_manage');
$$;

grant execute on function auth.read_mask(permissions_target,int) to web;

-- generic "mask one value" helper
-- probably remove this, actually. simpler to have type-specific ones,
-- even though it leads to the truckloads of redundant helpers below.
-- create function auth.mask_value(
-- 	p_mask bigint,
-- 	p_member permissions_member,
-- 	p_value anyelement
-- ) returns anyelement
-- language sql
-- immutable
-- as $$
-- 	select case
-- 		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
-- 		else null
-- 	end;
-- $$;

-- grant execute on function auth.mask_value(bigint,permissions_member,anyelement) to web;
--

create function auth.mask_text(p_mask bigint, p_member permissions_member, p_value text)
returns text
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_text(bigint,permissions_member,text) to web;


create function auth.mask_point(p_mask bigint, p_member permissions_member, p_value point)
returns point
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_point(bigint,permissions_member,point) to web;


create function auth.mask_path(p_mask bigint, p_member permissions_member, p_value path)
returns path
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_path(bigint,permissions_member,path) to web;


create function auth.mask_timestamp(p_mask bigint, p_member permissions_member, p_value timestamp)
returns timestamp
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_timestamp(bigint,permissions_member,timestamp) to web;


create function auth.mask_int(p_mask bigint, p_member permissions_member, p_value int)
returns int
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_int(bigint,permissions_member,int) to web;


create function auth.mask_bool(p_mask bigint, p_member permissions_member, p_value bool)
returns bool
language sql immutable
as $$
	select case
		when (p_mask & auth.member_bit(p_member)) <> 0 then p_value
		else null
	end;
$$;

grant execute on function auth.mask_bool(bigint,permissions_member,bool) to web;


create function auth.mask_has(p_mask bigint, p_member permissions_member)
returns boolean
language sql immutable
as $$
	select (p_mask & auth.member_bit(p_member)) <> 0;
$$;

grant execute on function auth.mask_has(bigint,permissions_member) to web;

commit;