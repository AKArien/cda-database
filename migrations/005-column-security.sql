begin;
select _v.register_patch('005-column-security', ARRAY['004-rls-rules'], NULL);

create function auth.member_bit(p_member permissions_member)
returns bigint
language sql
immutable
as $$
	select case p_member
		when 'lifetime' then (1::bigint << 0)
		when 'session_time' then (1::bigint << 1)
		when 'change_pass' then (1::bigint << 2)
		when 'non_sensitive' then (1::bigint << 3)

		when 'info' then (1::bigint << 8)
		when 'location' then (1::bigint << 9)
		when 'reports' then (1::bigint << 10)

		-- not a “real column”, but sometimes convenient:
		-- treat 'all' as “everything we know about”
		when 'all' then
			((1::bigint << 0) |
			 (1::bigint << 1) |
			 (1::bigint << 2) |
			 (1::bigint << 3) |
			 (1::bigint << 8) |
			 (1::bigint << 9) |
			 (1::bigint << 10))
	end;
$$;

grant execute on function auth.member_bit(permissions_member) to web;


create unlogged table auth.session_read_masks (
	verification uuid not null,
	target_type permissions_target not null,
	target int not null,
	read_mask bigint not null,
	expires_at timestamp not null,
	primary key (verification, target_type, target)
);

-- hot path index (redundant with PK but explicit is fine)
create index session_read_masks_lookup
on auth.session_read_masks (verification, target_type, target);

-- web should not be able to insert/update directly; only via SECURITY DEFINER function
grant select on auth.session_read_masks to web;

create function auth.compute_read_mask(
	p_target_type permissions_target,
	p_target int
) returns bigint
language sql
stable
as $$
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
	select coalesce(
		bit_or(auth.member_bit(p.member)),
		0::bigint
	)
	from permissions p
	join receiver_set r
	  on r.receiver_type = p.receiver_type
	 and r.receiver = p.receiver
	join target_set t
	  on t.target_type = p.target_type
	 and t.target = p.target
	where p.action = 'read';
$$;

grant execute on function auth.compute_read_mask(permissions_target,int) to web;


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