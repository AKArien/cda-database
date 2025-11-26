# Migrations

The database uses (Versioning)[https://gitlab.com/depesz/Versioning] to handle migrations.

Patches are written in the `migrations` directory and added to `timeline.sql`. This file simply tries to execute every migration, with Versioning telling apart what was already applied and what should be ran. As such, applied to any database, it yields the same result wether it is clean or stopped somewhere along the history. Thus, it’s history must not be modified without accepting that things will break.

The one-time setup is `init.sql`. Run it once per postgres instance. Note it does not call timeline.sql itself.

To apply migrations, simply connect to your database and run :
```sql
\i timeline.sql
```

# Auth

PostgREST views and functions are authenticated by a JSON Web Token. A user is considered authenticated if the `verification` claim is verified and matches a record in an unlogged table to implement a session mechanism. This is enforced with postgREST pre validation

# Schema

## Tables

reports (time series)
- time pkey timestamp
- watcher id pkey
- diff
-

sites
- id pkey
- name text
- human-readable information text
- perimeter path

local admins
- id pkey
- site id fkey
- location point

watchers
- id pkey
- gateway fkey
- location point
- signature

# Rest api endpoints

The project uses postgREST to propose an authenticated REST api. The following endpoints are exposed :

# Triggers

# Functions
