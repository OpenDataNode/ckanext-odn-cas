import logging
import uuid
import pkg_resources
import re
import pylons

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.logic as logic
import ckan.model as model
import ckan.logic.schema as schema
from ckanext.cas.config import RolesConfig

NotFound = logic.NotFound

log = logging.getLogger('ckanext.odn.cas')

def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


def user_create(context, data_dict):
    msg = toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


def user_update(context, data_dict):
    msg = toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)

def make_password():
    # create a hard to guess password
    out = ''
    for n in xrange(8):
        out += str(uuid.uuid4())
    return out

rememberer_name = None

def delete_cookies():
    global rememberer_name
    log.info("deleting cookies")
    if rememberer_name is None:
        plugins = toolkit.request.environ['repoze.who.plugins']
        cas_plugin = plugins.get('casauth')
        if cas_plugin:
            rememberer_name = cas_plugin.rememberer_name
            log.info(u"rememberer_name: {0}".format(rememberer_name))
        else:
            log.info("no casauth plugin")
    
    if rememberer_name:
        base.response.delete_cookie(rememberer_name)
        # We seem to end up with an extra cookie so kill this too
        domain = toolkit.request.environ['HTTP_HOST']
        base.response.delete_cookie(rememberer_name, domain='.' + domain)

class CasPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IRoutes, inherit = True)
    cas_identify = None
    
    def before_map(self, map):
        map.connect(
            'cas_unauthorized',
            '/cas_unauthorized',
            controller='ckanext.cas.plugin:CasController',
            action='cas_unauthorized'
        )
        return map
    
    
    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset,
        }
    
    def configure(self, config):
        self.cas_url = config.get('ckanext.cas.url', None)
        self.ckan_url = config.get('ckan.site_url', None)
        log.info(u'cas url: {0}'.format(self.cas_url))
        
        # loading roles from properties file
        default_cfg = pkg_resources.resource_filename(__name__, 'cas_roles.properties')
        cas_role_config_path = config.get('ckanext.odn.cas.role.config.path', default_cfg)
        log.info(u'Using roles properties file: {0}'.format(cas_role_config_path))
        self.roles_config = RolesConfig(cas_role_config_path)
        
        self.is_updating_allowed = config.get('ckan.odn.cas.allow_updating', 'False')
        self.is_updating_allowed = self.is_updating_allowed.lower() == 'true' 
        log.info(u'is_updating_allowed: {0}'.format(self.is_updating_allowed))
        
    
    def identify(self):
        log.info('identify')
        c = toolkit.c
        environ = toolkit.request.environ
        org_id = environ.get('REMOTE_USER', '')
        log.info(u'org_id {0}'.format(org_id))
        
        if org_id:
            #if not self.cas_identify:          
            identity = environ.get("repoze.who.identity", {})
            log.info(u'identity: {0}'.format(identity.keys()))
            user_data = identity.get("attributes", {})
            user_id = None
            
            log.info(u'attributes: {0}'.format(user_data))
            
            if user_data:
                self.cas_identify = user_data
                user_id = self._get_first_value(user_data.get(self.roles_config.attr_actor_id, None))
            if not (user_data or org_id):
                log.info("redirect to logged_out")
                delete_cookies()
                h.redirect_to(controller='user', action='logged_out')
                
            log.info(u'actor id : {0}'.format(user_id))
            log.info(u'actor id from session: {0}'.format(pylons.session.get('ckanext-cas-actorid')))
                        
            # create actor
            if user_id and not model.User.get(user_id):
                name_first = self._get_first_value(user_data[self.roles_config.attr_name_first])
                name_last = self._get_first_value(user_data[self.roles_config.attr_name_last])
                fullname = u'{0} {1}'.format(name_first, name_last)
                self.create_user(user_id, fullname)
            elif user_id and self.is_updating_allowed:
                self._check_and_update_user(c, user_id, user_data)
            
            if user_id:
                pylons.session['ckanext-cas-actorid'] = user_id
                pylons.session.save()
            
            # create organization user
            if org_id:
                if not model.User.get(org_id):
                    self.create_user(org_id, org_id)
                self._login_user(org_id)
            
            # create organization
            if user_data:
                user_cas_roles = user_data.get(self.roles_config.attr_roles, [])
                
                if isinstance(user_cas_roles, basestring):
                    user_cas_roles = [user_cas_roles]
                
                for cas_role in user_cas_roles:
                    user_role = self.roles_config.get_role(cas_role)
                    
                    if not user_role:
                        log.error(u'No CAS role configured for user CAS role \'{0}\''\
                                  .format(cas_role))
                        continue
                    
                    group_name = user_role.group_name
                    group_role = user_role.group_role
                    if user_role.is_org:
                        #org_id = self._get_first_value(user_data.get(self.roles_config.attr_org_id, None))
                        self.create_organization(org_id or group_name, group_role)
                    else:
                        self.create_group(group_name, group_role)
        else:
            # don't redirect API, resource files, datastore dumps
            do_redirect = not re.match(".*/api(/\\d+)?/action/.*", environ['PATH_INFO']) \
                and not re.match(r".*/dataset/.+/resource/.+/download/.+", environ['PATH_INFO']) \
                and not re.match(r".*/datastore/dump/.+", environ['PATH_INFO'])
                    
            if do_redirect:
                log.info("redirect to login")
                delete_cookies()
                h.redirect_to(controller='user', action='login')
    
    def _login_user(self, user_id):
        log.debug(u'logging in as {0}'.format(user_id))
        c = toolkit.c
        c.user = user_id
        c.userobj = model.User.get(c.user)
    
    def create_user(self, user_id, fullname):
        log.info(u"creating new user: {0}".format(user_id))
        # Create the user
        data_dict = {
            'password': make_password(),
            'name' : user_id,
            #'email' : self.cas_identify['Actor.Email'],
            'fullname' :  fullname,
            'id' : user_id
        }
                
        user_schema = self._get_user_validation_schema()
        context = {'schema' : user_schema, 'ignore_auth': True}
        user = toolkit.get_action('user_create')(context, data_dict)
#         c.userobj = model.User.get(c.user)
    
    def _check_and_update_user(self, c, user_id, user_data):
        userobj = model.User.get(user_id)
        
        name_first = self._get_first_value(user_data[self.roles_config.attr_name_first])
        name_last = self._get_first_value(user_data[self.roles_config.attr_name_last])
        fullname = u'{0} {1}'.format(name_first, name_last)
        if userobj.name != user_id or userobj.fullname != fullname:
            log.info('updating user')
            data_dict = {
                'id': user_id,
                'name': user_id,
                'fullname' : fullname,
                'password': make_password(),
            }
            user_schema = self._get_user_validation_schema()
            context = {'schema' : user_schema, 'ignore_auth': True}
            return toolkit.get_action('user_update')(context, data_dict)
        
    
    def _get_user_validation_schema(self):
        # Update the user schema to allow user creation
        user_schema = schema.default_user_schema()
        user_schema['id'] = [toolkit.get_validator('not_empty'), unicode]
        user_schema['name'] = [toolkit.get_validator('not_empty'), unicode]
        user_schema['email'] = [toolkit.get_validator('ignore_missing'), unicode]
        return user_schema
    
    def _get_first_value(self, data):
        if not data or isinstance(data, basestring):
            return data
        elif isinstance(data, list):
            return data[0]
        else:
            log.warning(u"Not list nor string: {0}".format(data))
            return data
        
    def login(self):
        log.info('login')
        if not toolkit.c.user:
            # A 401 HTTP Status will cause the login to be triggered
            log.info('login required')
            return base.abort(401)
            #return base.abort(401, toolkit._('Login is required!'))
        log.info("redirect to dashboard")
        h.redirect_to(controller='user', action='dashboard')
        
    def logout(self):
        log.info('logout')
        
        pylons.session['ckanext-cas-actorid'] = None
        pylons.session.save()
        
        if toolkit.c.user:
            log.info('logout abort')
            environ = toolkit.request.environ
            self.cas_identify = None
            subject_id = environ["repoze.who.identity"]['repoze.who.userid']
            client_auth = environ['repoze.who.plugins']["auth_tkt"]
            log.info(u'auth tkt methods: {0}'.format(dir(client_auth)))
            client_cas = environ['repoze.who.plugins']["casauth"]
            log.info(u'cas methods: {0}'.format(dir(client_cas)))
            environ['rwpc.logout']= self.ckan_url
        
        
    def abort(self, status_code, detail, headers, comment):
        log.info('abort')
        if (status_code == 401 and (toolkit.request.environ['PATH_INFO'] != '/user/login' or toolkit.request.environ['PATH_INFO'] != '/user/_logout')):
                h.redirect_to('cas_unauthorized')
        return (status_code, detail, headers, comment)
    
    def create_group(self, group_name, user_capacity='member'):
        group = model.Group.get(group_name)
        c = toolkit.c
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        log.info(u'site user: {0}'.format(site_user))
        if not group:
            log.info(u'creating group: {0}'.format(group_name))      
            context = {'user': site_user['name']}
            data_dict = {'id': group_name,
                         'name': group_name.lower(),
                         'title': group_name
            }
            group = toolkit.get_action('group_create')(context, data_dict)
            group = model.Group.get(group_name.lower())

        self._change_user_capacity(group, c.userobj.id, user_capacity)


    def create_organization(self, org_name, user_capacity='member'):
        org = model.Group.get(org_name)
        c = toolkit.c
        if not org:
            log.info(u'creating org: {0}'.format(org_name))
            context = {'user': c.userobj.id, 'ignore_auth': True}
            data_dict = {'id': org_name,
                         'name': org_name.lower(),
                         'title': org_name
            }
            org = toolkit.get_action('organization_create')(context, data_dict)
            org = model.Group.get(org_name.lower())
            
        self._change_user_capacity(org, c.userobj.id, user_capacity)


    def _change_user_capacity(self, group_org, user_id, user_capacity):
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        c = toolkit.c
        
        # check if we are a member of the group / organization
        data_dict = {
            'id': group_org.id,
            'object_type': 'user',
        }
        
        if self.is_updating_allowed:
            # thanks to this, it will update capacity
            data_dict['capacity'] = user_capacity
            
        members = toolkit.get_action('member_list')(context, data_dict)
        members = [member[0] for member in members]
        if c.userobj.id not in members:
            # add membership or update the capacity of member
            log.info('adding member to group / org or updating his capacity (role)')            
            member_dict = {
                'id': group_org.id,
                'object': user_id,
                'object_type': 'user',
                'capacity': user_capacity,
            }
            member_create_context = {
                'user': site_user['name'],
                'ignore_auth': True,
            }

            toolkit.get_action('member_create')(member_create_context, member_dict)

class CasController(base.BaseController):

    def cas_unauthorized(self):
        # This is our you are not authorized page
        c = toolkit.c
        c.code = 401
        c.content = toolkit._('You are not authorized to do this')
        return toolkit.render('error_document_template.html')





