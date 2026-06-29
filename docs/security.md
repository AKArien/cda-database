# Security

## Authentication

Authentication is, much like everything else, handled directly in the database. Accesses have a password/phrase (which is of course salted and hashed), which can be used to generate a session.

A session is also stored in a database table. A JWT is issued upon login and signed, and is expected to be stored by the client (presumably in cookies). PostgREST views and functions are authenticated by it’s `verification` claim. This is enforced with postgREST pre validation function, which errors out on a lack of session. As the service is completely private, without being authenticated, only logging in is open without the a valid session.

## Permissions

Permissions are managed through a « sentence-like » system : an entry into the permissions index is comprised of a permitted action, an owner (which entity gets the permission), a target and which fields are authorised.

« Manage » permissions over an on-site entity allows the permissions owner to grant the permissions to another user that they have manage permissions over.

Permissions are enforced first by RLS policies, which filter out rows that the user doesn’t have any permissions over. Access to this data is regulated via views in the `api` schema, which masks colums which are not authorised to be seen.
