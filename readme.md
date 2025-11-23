# Migrations

The database uses (Versioning)[https://gitlab.com/depesz/Versioning] to handle migrations. To migrate, simply connect to the database and run :
```sql
source ./path/to/migrations/xxx-target.sql
```
Versioning will handle conflicts and dependancies.

# Auth

PostgREST views and functions are authenticated by a JSON Web Token. A user is considered authenticated if the `verification` claim is verified and matches a record in an unlogged table to implement a session mechanism. This is enforced with postgREST pre validation

# Schema

## Types

- gps coordinates location

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
- perimeter location[] -- needs constraint ?

local admins
- id pkey
- site id fkey
- location

watchers
- id pkey
- gateway fkey
- location
- signature

users
- id pkey
- name unique -- given by the organisation
- pass
- role

# Rest api endpoints

The project uses postgREST to propose an authenticated REST api. The following endpoints are exposed :

# Triggers

# Functions
