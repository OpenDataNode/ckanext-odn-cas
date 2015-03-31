ckanext-odn-cas
-------

CAS auth for CKAN

Installation
-------

(Optional): activate ckan virtualenv ``` . /usr/lib/ckan/default/bin/activate ```

From the extension folder start the installation: ``` python setup.py install ```

Add extension to ckan config: /etc/ckan/default/production.ini

```ApacheConf
ckan.plugins = odn_cas
```

Other properties:

```ApacheConf
# needed for proper redirect after logout
ckan.site_url = http://my_ckan.org

# absolute path to roles config files, if not given ckanext/cas/cas_roles.properties is used
ckanext.odn.cas.role.config.path = /etc/ckan/default/roles.properties
```

Example properties looks like:

```
[role]
role.attribute.name.org.id = SubjectID
role.attribute.name.roles = SPR.Roles
role.attribute.name.user.name.first = first_name
role.attribute.name.user.name.last = last_name

[role.1]
role.spr = MOD-R-PO
role.group.name = app-admin
role.is.org = True

[role.2]
...
```

Note: There may be more roles, just the section name needs to start with 'role.'

Internationalization (i18n)
-------
CKAN supports internationalization through babel (```pip install babel```). This tool extracts the messages from source code and html files
and creates .pot file. Next using commands (step 2 or 3) it creates or updates .po files. The actual translation are in these .po files.

1. To extract new .pot file from sources
	```
	python setup.py extract_messages
	```
	
	This need to be done if there is no .pot file or there were some changes to messages in source code files or html files.

2. To generate .po for new localization (this example uses 'sk' localization)
	```
	python setup.py init_catalog --locale sk
	```

3. If only updating existing .po file (e.g. new messages were extracted through step 1)
	```
	python setup.py update_catalog --locale sk
	```

Licenses
-------

?
