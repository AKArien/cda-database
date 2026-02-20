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
	a_group int references auth.accesses(id),
	primary key (access, a_group)
);

/*
permissions management is as such :
A user has certain privileges on certain tables and certain groups.
The privileges are read, grant and revoke.
Additionally, permission are between members (field of tables) of certain entities, either relating to the on-site equipment or the user(s).
A permission over a group includes every member of this group, while a permission over a gateway includes all of it’s handled watchers, and a permission over a site includes all of it’s gateways.
A read permission allows a member to see details of the specified member of it’s target.
A grant permission allows it to grant others the read permission, and revoke to remove. Both imply a read permission.
With the « propagate » variants, the recipient can also transmit these to other users.
A user needs to have appropriate permissions over a table to grant permissions on it to the users they have permissions over. Example :
	To grant read access to a group, a user needs at least « grant » access to a table, as well as « grant » access to this group.
*/

create type permissions_verb as enum (
	'read',
	'grant',
	'grant_propagate',
	'revoke',
	'revoke_propagate'
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

-- members specific to accesses. applied to a group, it gives the permissoin to every access in said group
create type permissions_members_accesses as enum (
	'lifetime',
	'session_time',
	'change_pass'
);

--  members specific to on-site equipment. applies uniformally and recursively for sites, gateways and watchers
create type permissions_members_on_site as enum (
	'info',
	'location',
	'reports'
);

create type permissions_members as enum (
	'permissions_members_accesses',
	'permissions_members_on_site'
);

create table permissions (
	-- to make it easier to understand how permissions work, let’s make this look like a formal adminstrative declaration :
	-- i,
	granted_by int references auth.accesses(id),
	-- hereby declare that
	reciever int,
	-- of type
	reciever_type permissions_owner,
	-- is to be trusted with
	action permissions_verb, --ing
	-- but not / and delegating this trust
	propagate bool,
	-- over the 
	member permissions_members,
	-- of
	target int,
	-- of type
	target_type permissions_target,

	primary key (reciever, reciever_type, action, member, target, target_type)
);

create function check_permissions_validity()
returns trigger as $$
begin
	-- verify receiver is valid
	if NEW.reciever_type = 'access' then
		if not exists (
			select id from auth.accesses where id = NEW.reciever
		) then
			raise exception 'Invalid input data: reciever invalid';
		end if;
	elsif NEW.reciever_type = 'a_group' then
		if not exists (
			select id from accesses_group where id = NEW.reciever
		) then
			raise exception 'Invalid input data: reciever invalid';
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

	-- permissions checks occur in row level security
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