begin;
select _v.register_patch('003-permissions-management', ARRAY['002-auth'], NULL);

-- create schema permissions; -- todo : determine if we want that or not

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
permissions management is as such :
A user has certain privileges on certain tables and certain groups.
The privileges are read, grant and revoke.
Additionally, permission are between members (field of tables) of certain entities, either relating to the on-site equipment or the user(s).
A permission over a group includes every member of this group, while a permission over a gateway includes all of it’s handled watchers, and a permission over a site includes all of it’s gateways.
A read permission allows a member to see details of the specified member of it’s target.
A grant permission allows it to grant others the read permission, and revoke to remove.
With the « propagate » boolean of the permissions table, the recipient can also transmit these to other users.
A user needs to have appropriate permissions over a table to grant permissions on it to the users they have permissions over. Examples :
	To grant read access to a group, a user needs at least « grant » access to a table, as well as « grant » access to this group.
*/

create type permissions_verb as enum (
	'read',
	'grant',
	'revoke',
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

	-- members specific to accesses. applied to a group, it gives the permissoin to every access in said group
	'lifetime',
	'session_time',
	'change_pass',

	--  members specific to on-site equipment. applies uniformally and recursively for sites, gateways and watchers
	'info',
	'location',
	'reports'
);

create table permissions (
	-- to make it easier to understand how permissions work, let’s make this look like a formal adminstrative declaration :
	-- i,
	granted_by int references auth.accesses(id),
	-- hereby declare that
	receiver int not null,
	-- of type
	receiver_type permissions_owner not null,
	-- is to be trusted with
	action permissions_verb not null, --ing
	-- but not / and delegating this trust
	propagate bool not null,
	-- over the 
	member permissions_members not null,
	-- of
	target int not null,
	-- of type
	target_type permissions_target not null,

	-- members are only applicable with certain targets
	constraint member_matches_target_type check (
	(
		target_type in ('site','gateway','watcher')
		and member in ('info','location','reports')
	)
	or
	(
		target_type in ('access','a_group')
		and member in ('lifetime','session_time','change_pass')
	)
)
	primary key (receiver, receiver_type, action, member, target, target_type)
);

create index permissions_lookup_direct
on permissions (target_type, target, action, member);

create index permissions_lookup_receiver_access
on permissions (receiver_type, receiver);

create index access_in_group_lookup
on access_in_group (access, a_group);

create index permissions_lookup_receiver_first
on permissions (receiver_type, receiver, action, member, target_type, target);

create function check_permissions_validity()
returns trigger as $$
begin
	-- verify receiver is valid
	if NEW.receiver_type = 'access' then
		if not exists (
			select id from auth.accesses where id = NEW.receiver
		) then
			raise exception 'Invalid input data: receiver invalid';
		end if;
	elsif NEW.receiver_type = 'a_group' then
		if not exists (
			select id from accesses_group where id = NEW.receiver
		) then
			raise exception 'Invalid input data: receiver invalid';
		end if;
	end if;

	-- verify target is valid
	if NEW.target_type = 'access' then
		if not exists (
			select id from auth.accesses where id = NEW.target
		) then
			raise exception 'Invalid input data: target invalid';
		end if;
	elsif NEW.target_type = 'a_group' then
		if not exists (
			select id from accesses_group where id = NEW.target
		) then
			raise exception 'Invalid input data: target invalid';
		end if;
	elsif NEW.target_type = 'site' then
		if not exists (
			select id from sites where id = NEW.target
		) then
			raise exception 'Invalid input data: target invalid';
		end if;
	elsif NEW.target_type = 'gateway' then
		if not exists (
			select id from gateways where id = NEW.target
		) then
			raise exception 'Invalid input data: target invalid';
		end if;
	elsif NEW.target_type = 'watcher' then
		if not exists (
			select id from watchers where id = NEW.target
		) then
			raise exception 'Invalid input data: target invalid';
		end if;
	end if;



	return NEW;
end;
$$ language plpgsql;

create trigger enforce_check_permissions_validity
	before insert or update
	on permissions
	for each row
	execute function check_permissions_validity()
;

commit;