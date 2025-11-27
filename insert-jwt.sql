\getenv jwt_secret JWT_SECRET

alter database cda set "app.jwt_secret" to :jwt_secret;
