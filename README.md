# GoLDAPQuery 
![GoLDAPQuery](goldapquery.png)  
Not to be confused with GOLD apquery, this is GoLDAPQuery


## What's it for?
This tool is intended to simplify searching LDAP for various objects.  
It will support multiple operating systems out of the box, thanks to it being writen in Go.   
Using ldapsearch is somewhat of a drag and I was hoping to provide a tool  
for those so inclined to perform raw ldapsearches that isnt a complete nightmare to use.  
The user of the tool will need to know certain details to use it of course, like the ldap server,  
have an understanding of what bind methods are supported on the endpoint,and knowledge of valid creds,etc.


## Initial features:   
- [x] Prompt for user creds  
- [ ] Store creds in environment variable  
- [ ] Search and list specific types of objects  
    - [x] computers  
    - [x] users  
    - [ ] user specified
- [ ] Support different bind types, Anonymous, Simple Bind, GSSAPI, and SASL  
    - [x] anonymous  
    - [x] simple  
    - [x] ntlm  
    - [x] ntlm with PTH  
    - [ ] GSSAPI  
    - [ ] SASL  
- [ ] Support dumping the entire database  
- [x] Support ldaps and ldap  


## Stretch goals

- Allow for addition, deletion, and modification of existing LDAP entries  
- Potentially support BloodHound(Need to look into this more)  
