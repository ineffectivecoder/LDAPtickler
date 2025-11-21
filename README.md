# LDAPtickler
![LDAPtickler](ldaptickler.png)  
Tickler of LDAP


## What's it for?
This tool is intended to simplify searching LDAP for various objects.  
It will support multiple operating systems out of the box, thanks to it being written in Go.   
Using ldapsearch is somewhat of a drag and I was hoping to provide a tool  
for those so inclined to perform raw ldapsearches that isn't a complete nightmare to use.  
The user of the tool will need to know certain details to use it of course, like the ldap server,  
have an understanding of what bind methods are supported on the endpoint, basedn,and knowledge of valid creds,etc.

This tool has grown significantly to also allow for modification of certain fields that may be useful to a Red Team operator,
as well as the incorporation of many queries for spot checking the configuration of many AD attributes.   
This has been tested extensively against Windows 2025 Server running Active Directory.  
Be extremely careful when arbitrarily modifying or deleting entries in AD, it can lead to all sorts of unexpected behavior.
I personally have destroyed my domain a few times now leveraging this tool. 


## Initial features:   
- [x] Prompt for user creds  
- [x] Changing a user's password   
- [x] Creation of user accounts
- [x] Modification of Service Principal Names
- [x] Creation of machine accounts
    -[x] Research why only my DA can do this. This is now sorted out. This very much depended on the specific entries being created for the machine account.
- [x] Deletion of User and Machine accounts
- [x] Expand ldapsearch function to take all supported parameters, currently just filter, attributes, basedn, and scope  
- [ ] Store creds in environment variable  
- [x] Refactor
    - [x] Create Library
- [ ] Support Adding and removing of all delegation attributes  
    - [x] Unconstrained - Refactored
    - [x] Constrained  - Refactored
    - [x] Resource Based Constrained Delegation, support has been added for validation, adding and removing. Remove only supports all for now. Need to fix.   
- [ ] Support modification of msds-keycredentiallink for shadow credentials  
    - [ ] Create self signed cert  
    - [ ] Prepare blob for placement in msds-keycredentiallink field  
    - [ ] Modify msds-keycredentiallink field   
- [ ] Support creation of DNS entires
- [x] Search and list specific types of objects  
    - [x] Partial support for most useful DNS entries, many other types need work
    - [x] Domain Controllers
    - [x] DNS entries
    - [x] computers  
    - [x] users  
    - [x] groups
    - [x] kerberoastable users
    - [x] user specified
    - [x] Unconstrained ,Constrained Delegation and RBCD
    - [x] Shadow Credentials
    - [x] Protected Users Group
    - [x] Kerberos Pre-Authenticated Disabled
    - [x] Users who dont require a password
    - [x] Users set to require password change at next login
    - [x] Users set to have the password never expire
    - [ ] Pull down schema - need to research this more, I can pull down the top level, beyond that is HUUUUUGE and am limited by LDAP itself
    - [x] Query description field of all objects
    - [x] Query ms-DS-MachineAccountQuota

- [ ] Support different bind types, Anonymous, Simple Bind, GSSAPI, and SASL  
    - [x] anonymous  
    - [x] simple  
    - [x] ntlm  
    - [x] ntlm with PTH  
    - [x] GSSAPI  
    - [ ] SASL  
- [ ] Support dumping the entire database  
- [x] Support ldaps and ldap  


## Stretch goals

- [x] Allow for deletion, and modification of existing LDAP entries  
- Potentially support BloodHound(Need to look into this more)  


## Updates
Fixed issue when setting UserAccountControl for machine accounts. Before I was just blowing away the prior setting and replacing.  
It was determined this was silly. Now grabbing the previous UAC setting and doing bit math to add the desired setting.  
This paves the way to do the same for user accounts.    
GSSAPI is now implemented thanks to the latest PRs to the go-ldap package.

## TODO


## Thanks
### This wouldnt be possible without the following people:  
- [mjwitta](https://github.com/mjwhitta/)     
- [dumpst3rfir3](https://github.com/dumpst3rfir3/)   
- [sludgework](https://github.com/sludgework)  

### Without the below package none of this would be possible
- [go-ldap](https://github.com/go-ldap/ldap)  