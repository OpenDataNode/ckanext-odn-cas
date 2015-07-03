'''
Created on 18.3.2015

@author: mvi
'''

import ConfigParser

import ckan.logic as logic
NotFound = logic.NotFound
DEFAULT_SECTION = 'role'
ATTR_ORG_ID = 'role.attribute.name.org.id'
ATTR_ROLES = 'role.attribute.name.roles'
ATTR_NAME_FIRST = 'role.attribute.name.user.name.first'
ATTR_NAME_LAST = 'role.attribute.name.user.name.last'
ATTR_ACTOR_ID = 'role.attribute.actor.id'

class Role():
    
    def __init__(self, config, section):
        self.cas_role = config.get(section, 'role.name')
        self.group_name = config.get(section, 'role.group.name')
        self.group_role = config.get(section, 'role.group.role')
        self.is_org = config.getboolean(section, 'role.group.is_org')
        
        if self.group_role not in ['member', 'editor', 'admin']:
            raise logic.ValidationError('Group role not set for CAS role {0}'\
                                        .format(self.cas_role))
    
    def __str__(self):
        return "Role(cas_role = {self.cas_role}, group_role = {self.group_role}, group_name = {self.group_name}, is_org = {self.is_org})"\
            .format(self=self)
    
    def __repr__(self):
        return self.__str__()

class RolesConfig():
    
    def __init__(self, config_path):
        roles_config = ConfigParser.ConfigParser()

        if not roles_config.read(config_path):
            raise NotFound('Failed to find role properties file {0}'\
                           .format(config_path))
        
#         self.attr_org_id = roles_config.get(DEFAULT_SECTION, ATTR_ORG_ID)
        self.attr_roles = roles_config.get(DEFAULT_SECTION, ATTR_ROLES)
        self.attr_name_first = roles_config.get(DEFAULT_SECTION, ATTR_NAME_FIRST)
        self.attr_name_last = roles_config.get(DEFAULT_SECTION, ATTR_NAME_LAST)
        self.attr_actor_id = roles_config.get(DEFAULT_SECTION, ATTR_ACTOR_ID)
        
        self.cas_roles = []
        roles = [x for x in roles_config.sections() if x.startswith("role.")]
        for role in roles:
            role_obj = Role(roles_config, role)
            self.cas_roles.append(role_obj)
            
    def get_role(self, cas_role):
        for role in self.cas_roles:
            if role.cas_role == cas_role:
                return role
