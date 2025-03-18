# goldapsearch  
Not to be confused with GOLD apsearch, this is GO LDAPSEARCH


## What's it for?
This tool is intended to simplify searching LDAP for various objects.  
It will support multiple operating systems out of the box, thanks to it being writen in Go.   
Using ldapsearch is somewhat of a drag and I was hoping to provide a tool  
for those so inclined to perform raw ldapsearches that isnt a complete nightmare to use.  
The user of the tool will need to know certain details to use it of course, like the ldap server,  
have an understanding of what bind methods are supported on the endpoint,and knowledge of valid creds,etc.


## Initial features:   
- Prompt for user password rather than store in code and read in environment variable containing creds
- Search and list specific types of objects
- Support different bind types, Anonymous, Simple Bind, GSSAPI, and SASL
- Support dumping the entire database
- Support ldaps and ldap


## Stretch goals

- Allow for adding, deleting, and modification of existing LDAP entries
- Potentially support BloodHound(Need to look into this more)
