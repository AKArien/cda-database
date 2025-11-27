begin;
select _v.register_patch('003-permissions-management', ARRAY['002-auth'], NULL);

-- create schema permissions; 

create table accesses_group (
	id serial primary key,
	name text unique not null,
	description text,
	master_group int references accesses_group(id),
);

create table access_in_group (
	access int references accesses(id),
	group int references accesses(id),
	primary key (access, group),
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
	'revoke_propagate',
);

create type permission_owner as enum (
	'group',
	'access',
);

create type permission_target as enum (
	'access',
	'group',
	'site',
	'gateway',
	'watcher',
);

-- members specific to accesses. applied to a group, it gives the permissoin to every access in said group
create type permissions_members_accesses as enum (
	'lifetime',
	'session_time',
	'change_pass',
);

--  members specific to on-site equipment. applies uniformally and recursively for sites, gateways and watchers
create type permissions_members_on_site as enum (
	'info',
	'location',
	'reports',
);

create type permission_members as enum (
	'permissions_members_accesses',
	'permissions_members_on_site',
);

create table permissions (
	-- to make it easier to understand how permissions work, let’s make this look like a formal adminstrative declaration :
	-- i,
	granted_by int references auth.accesses(id),
	-- hereby declare that
	reciever int,
	-- of type
	reciever_type permission_owner,
	-- is to be trusted with
	action permission_verb, --ing
	-- but not / and delegating this trust
	propagate bool,
	-- over the 
	member permission_member,
	-- of
	target int,
	-- of type
	target_type permission_target,

	primary key (reciever, reciever_type, action, propagate, member, target, target_type),
);

commit;
