The database uses (Versioning)[https://gitlab.com/depesz/Versioning] to handle migrations, and setup is made reproducible by scripts. If anything is unclear, check the comments in the scripts, or the containerfile and the testing for an example usage.

# Auth

PostgREST views and functions are authenticated by a JSON Web Token. A user is considered authenticated if the `verification` claim is verified and matches a record in an unlogged table that keeps track of all « sessions ».

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

# Triggers

# Functions
