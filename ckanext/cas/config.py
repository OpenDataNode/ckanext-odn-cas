'''
Created on 18.3.2015

@author: mvi
'''

import ConfigParser
import pkg_resources

import ckan.logic as logic
NotFound = logic.NotFound

class Role():
    
    def __init__(self, config, section):
        self.group_name = config.get(section, 'role.group.name')
        self.spr_role = config.get(section, 'role.spr')
        self.is_org = config.getboolean(section, 'role.is.org')
    
    def __str__(self):
        return "Role(spr_role = {self.spr_role}, group_name = {self.group_name}, is_org = {self.is_org})"\
            .format(self=self)
    
    def __repr__(self):
        return self.__str__()

class RolesConfig():
    
    def __init__(self, config_path):
        roles_config = ConfigParser.ConfigParser()

        if not roles_config.read(config_path):
            raise NotFound('Failed to find role properties file {0}'\
                           .format(config_path))
        
        self.roles = []
        roles = [x for x in roles_config.sections() if x.startswith("role.")]
        for role in roles:
            role_obj = Role(roles_config, role)
            self.roles.append(role_obj)
            
    def get_role(self, spr_role):
        for role in self.roles:
            if role.spr_role == spr_role:
                return role
