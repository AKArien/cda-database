begin;
select _v.register_patch('003-permissions-management', ARRAY['002-auth'], NULL);

-- create schema permissions; -- todo : determine if we want that or not

create table accesses_group (
	id serial primary key,
	name text unique not null,
	description text
);

create table access_in_group (
	access int references auth.accesses(id),
	a_group int references accesses_group(id),
	primary key (access, a_group)
);

/*
permissions management is as such :
A user has certain privileges on certain tables and certain groups.
The privileges are read, manage_reads and manage_manage.

The meaning of the permission row is:
- receiver(_type) is trusted with `action` over `target(_type)`.
- for action='read', the `mask` is a bigint bitset of what members/columns can be read.
- for action in ('manage_reads','manage_manage'), mask is ignored for now (keep 0).

No delegation/propagation is modeled here.

We model creation rights with:
	action = 'create'

Semantics of target/mask for 'create':
- mask:
	- must be exactly auth.member_bit('all')
	- it is a convention marker (not a per-column mask for creation)
- target_type determines what can be created
- target encodes the creation scope, depending on target_type:

	- target_type = 'site':
		- target must be 0
		- grants ability to create any site (global scope)

	- target_type = 'access':
		- target must be 0
		- grants ability to create any access (global scope)

	- target_type = 'gateway':
		- target must be an existing sites.id
		- grants ability to create gateways under that site only

	- target_type = 'watcher':
		- target must be an existing gateways.id
		- grants ability to create watchers under that gateway only

Unsupported create target types are rejected by validation.

Rationale:
- encode creation scopes directly in permissions rows
- validate conventions at insert/update time
- keep runtime permission checks simple and cheap
*/

create type permissions_verb as enum (
	'read',
	'write',
	'create',
	'manage_reads',
	'manage_write',
	'manage_manage'
);

create type permissions_owner as enum (
	'access',
	'a_group'
);

create type permissions_target as enum (
	'access',
	'a_group',
	'site',
	'gateway',
	'watcher'
);

create type permissions_member as enum (
	'all',

	-- members specific to accesses. applied to a group, it gives the permission to every access in said group
	'non_sensitive',
	'lifetime',
	'session_time',
	'change_pass',

	-- members specific to on-site equipment. applies uniformly and recursively for sites, gateways and watchers
	'info',
	'location',
	'reports'
);

-- member -> bit mapping for read masks
create function auth.member_bit(p_member permissions_member)
returns bigint
language sql
immutable
as $$
	select case p_member
		when 'non_sensitive' then (1::bigint << 0)
		when 'lifetime' then (1::bigint << 1)
		when 'session_time' then (1::bigint << 2)
		when 'change_pass' then (1::bigint << 3)

		when 'info' then (1::bigint << 8)
		when 'location' then (1::bigint << 9)
		when 'reports' then (1::bigint << 10)

		-- not a "real column", but sometimes convenient:
		-- treat 'all' as "everything we know about"
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

-- (used by api views)
grant execute on function auth.member_bit(permissions_member) to web;

create table permissions (
	receiver int not null,
	receiver_type permissions_owner not null,

	action permissions_verb not null,

	-- for action='read' : bitset of members/columns that can be read on the target
	-- for other actions : reserved (should be 0)
	mask bigint not null default 0,

	target int not null,
	target_type permissions_target not null,

	primary key (receiver, receiver_type, action, target, target_type)
);

create index permissions_lookup_direct
on permissions (target_type, target, action);

create index permissions_lookup_receiver_access
on permissions (receiver_type, receiver);

create index access_in_group_lookup
on access_in_group (access, a_group);

create index permissions_lookup_receiver_first
on permissions (receiver_type, receiver, action, target_type, target);

create function check_permissions_validity()
returns trigger as $$
begin
	-- verify receiver is valid
	if NEW.receiver_type = 'access' then
		if not exists (
			select 1 from auth.accesses where id = NEW.receiver
		) then
			raise exception 'Invalid input data: receiver invalid';
		end if;
	elsif NEW.receiver_type = 'a_group' then
		if not exists (
			select 1 from accesses_group where id = NEW.receiver
		) then
			raise exception 'Invalid input data: receiver invalid';
		end if;
	end if;

	-- create permissions have dedicated scope semantics
	if NEW.action = 'create' then
		if NEW.mask is distinct from auth.member_bit('all') then
			raise exception 'Invalid input data: create mask must be auth.member_bit(''all'')';
		end if;

		if NEW.target <> 0 then
			raise exception 'Invalid input data: create permission requires target=0';
		end if;

		return NEW;
	end if;

	-- non-create: verify concrete target exists
	if NEW.target_type = 'access' then
		if not exists (select 1 from auth.accesses where id = NEW.target) then
			raise exception 'Invalid input data: target invalid';
		end if;
	elsif NEW.target_type = 'a_group' then
		if not exists (select 1 from accesses_group where id = NEW.target) then
			raise exception 'Invalid input data: target invalid';
		end if;
	elsif NEW.target_type = 'site' then
		if not exists (select 1 from sites where id = NEW.target) then
			raise exception 'Invalid input data: target invalid';
		end if;
	elsif NEW.target_type = 'gateway' then
		if not exists (select 1 from gateways where id = NEW.target) then
			raise exception 'Invalid input data: target invalid';
		end if;
	elsif NEW.target_type = 'watcher' then
		if not exists (select 1 from watchers where id = NEW.target) then
			raise exception 'Invalid input data: target invalid';
		end if;
	end if;

	-- read/write are masked actions
	if NEW.action in ('read', 'write') then
		if NEW.mask is null then
			raise exception 'Invalid input data: % mask cannot be null', NEW.action;
		end if;

		-- reject unknown bits
		if (NEW.mask & ~auth.member_bit('all')) <> 0 then
			raise exception 'Invalid input data: % mask contains unknown bits', NEW.action;
		end if;

		-- full wildcard accepted on every target type
		if NEW.mask = auth.member_bit('all') then
			return NEW;
		end if;

		-- otherwise enforce type-specific subsets
		if NEW.target_type in ('site', 'gateway', 'watcher') then
			if (NEW.mask & ~(auth.member_bit('info') | auth.member_bit('location') | auth.member_bit('reports'))) <> 0 then
				raise exception 'Invalid input data: % mask contains bits not applicable to this target type', NEW.action;
			end if;
		elsif NEW.target_type in ('access', 'a_group') then
			if (NEW.mask & ~(auth.member_bit('non_sensitive') | auth.member_bit('lifetime') | auth.member_bit('session_time') | auth.member_bit('change_pass'))) <> 0 then
				raise exception 'Invalid input data: % mask contains bits not applicable to this target type', NEW.action;
			end if;
		end if;

		return NEW;
	end if;

	-- management actions do not use masks
	if NEW.action in ('manage_reads', 'manage_write', 'manage_manage') then
		if NEW.mask <> 0 then
			raise exception 'Invalid input data: mask must be 0 for management actions';
		end if;
		return NEW;
	end if;

	raise exception 'Invalid input data: unsupported action=%', NEW.action;
end;
$$ language plpgsql;

create trigger enforce_check_permissions_validity
	before insert or update
	on permissions
	for each row
	execute function check_permissions_validity()
;

commit;
