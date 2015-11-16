from setuptools import setup, find_packages

version = '1.2.1-SNAPSHOT'

setup(
    name='ckanext-odn-cas',
    version=version,
    description="CAS auth for CKAN",
    long_description='''
    ''',
    classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='',
    author='Martin Virag, Dominik Kapisinsky',
    author_email='martin.virag@eea.sk',
    url='https://github.com/OpenDataNode/ckanext-odn-cas',
    license='AGPL',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext', 'ckanext.cas'],
    package_data={'': [
                       'i18n/*/LC_MESSAGES/*.po',
                       '**/*.properties',
                       ]
                  },
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        # -*- Extra requirements: -*-
    ],
    message_extractors={
        'ckanext': [
            ('**.py', 'python', None),
            ('**.html', 'ckan', None),
        ]
    }, # for babel.extract_messages, says which are source files for translating
    entry_points='''
        [ckan.plugins]
        # Add plugins here, e.g.
        odn_cas=ckanext.cas.plugin:CasPlugin
    ''',
)
