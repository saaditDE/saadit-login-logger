# SAAD-IT Login Logger
- This is a login attempt logger for WordPress
- Use at your own risk, no liability. Written with best intentions and good-will. It might have unexpected flaws, which are not yet known
- Written just for fun, other sources are mentioned in the plugin php file

## Features
- Can log all login attempts (successful, failed, real user, non-sense)
- Stores the failed passwords, redacts passwords when successful login attempt (to avoid sensitive information leaks)
- Logfile is a phpfile, protecting the sensitive information
- built-in time-based rate limiting (3 seconds)
- built-in log rotation (after 30 days or 10k lines)
- no readme.txt in the zip

![ss_saadit_logger.png](https://github.com/saaditDE/saadit-login-logger/blob/main/screenshots/ss_saadit_logger.png?raw=true)
