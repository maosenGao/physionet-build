from os import walk, chdir, listdir, path
import pdb

from oauth2client.service_account import ServiceAccountCredentials
from google.api_core.exceptions import BadRequest
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build
from django.contrib import messages
from google.cloud import storage
from django.conf import settings

import logging

LOGGER = logging.getLogger(__name__)
Public_Roles = ['roles/storage.legacyBucketReader', 'roles/storage.legacyObjectReader',
    'roles/storage.objectViewer']

def check_bucket(project, version):
    """
    Function to check if a bucket already exists 
    """
    storage_client = storage.Client()
    domain = 'physionet.org'
    if 'production' not in settings.SETTINGS_MODULE:
        domain = 'testing-delete.' + domain
    bucket_name = '{0}-{1}.{2}'.format(project, version, domain)
    exists = storage_client.lookup_bucket(bucket_name)
    if exists:
        return bucket_name
    return False

def create_bucket(project, version, title, protected=False):
    """
    Function to create a bucket and set its permissions
    """
    storage_client = storage.Client()
    domain = 'physionet.org'
    if 'production' not in settings.SETTINGS_MODULE:
        domain = 'testing-delete.' + domain
    bucket_name = '{0}-{1}.{2}'.format(project, version, domain)
    bucket = storage_client.create_bucket(bucket_name)
    bucket = storage_client.bucket(bucket_name)
    bucket.iam_configuration.bucket_policy_only_enabled = True
    bucket.patch()
    LOGGER.info("Created bucket {0} for project {1}".format(bucket_name.lower(), project))
    if not protected:
        make_bucket_public(bucket)
    else:
        remove_bucket_permissions(bucket)
        group = create_grant_access_group(bucket, project, version, title)
        return bucket_name, group
    return bucket_name, None

def make_bucket_public(bucket):
    """
    Function to make a bucket public to all users 
    """
    policy = bucket.get_iam_policy()
    for role in Public_Roles:
        policy[role].add('allUsers')
    bucket.set_iam_policy(policy)
    LOGGER.info("Made bucket {} public".format(bucket.name))

def remove_bucket_permissions(bucket):
    """
    Function to remove all permissions from bucket but owner 
    """
    policy = bucket.get_iam_policy()
    to_remove = []
    for role in policy:
        if role != 'roles/storage.legacyBucketOwner':
            for member in policy[role]:
                to_remove.append([role, member])
    for item in to_remove:
        policy[item[0]].discard(item[1])
    if to_remove:
        bucket.set_iam_policy(policy)
        LOGGER.info("Removed all read permissions from bucket {}".format(bucket.name))

def create_grant_access_group(bucket, project_slug, version, title):
    """
    Function to automatically create organizational group emails
    that manage access to private projects.
    """
    email = '{0}-{1}@physionet.org'.format(project_slug, version)
    if 'production' not in settings.SETTINGS_MODULE:
        email = 'testing-delete-{0}-{1}@physionet.org'.format(project_slug, version)

    service = create_directory_service(settings.GCP_DELEGATION_EMAIL)
    # Get all the members of the Google group
    try:
        found = False
        outcome = service.groups().list(domain='physionet.org').execute()
        for group in outcome['groups']:
            if group['email'] == email:
                found = True
        if not found:
            creation = service.groups().insert(body={'email': email,
                'name': '{0} v{1}'.format(title, version),
                'description': 'Group that handles the access for the PhysioNet \
                project {0} version {1}'.format(title, version)}).execute()
            if creation['kind'] == 'admin#directory#group':
                service = create_directory_service(settings.GCP_DELEGATION_EMAIL, group=True)
                update = service.groups().update(groupUniqueId=email, body={
                    'allowExternalMembers':'true',
                    'whoCanPostMessage':'ALL_OWNERS_CAN_POST',
                    'whoCanModerateMembers':'OWNERS_AND_MANAGERS',
                    'whoCanJoin': 'INVITED_CAN_JOIN'}).execute()
                if update['kind'] == 'groupsSettings#groups':
                    LOGGER.info("The access group {0} was succesfully created".format(
                        email))
                    return email
                LOGGER.info("There was an error {0} setting the \
                    permissions of the group {1}".format(update, email))
            LOGGER.info("There was an error {0} creating the group {1}".format(
                creation, email))
            return False
        return False
    except HttpError as e:
        if json.loads(e.content)['error']['message'] == 'Member already exists.':
            return False
        else:
            LOGGER.info('Unknown error {0} creating the group {1} for \
            access to {1}'.format(e.content, email, project_slug))
            raise e


def add_email_bucket_access(project, email, group=False):
    """
    Function to add access to a bucket from a email 
    If the email is elegible to be used in GCP the set iam policy will pass
    If not, it will return a error as a bad requet.
    """
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(project.gcp.bucket_name)
    policy = bucket.get_iam_policy()
    if group:
        for role in Public_Roles:
            policy[role].add('group:'+email)
    else:
        for role in Public_Roles:
            policy[role].add('user:'+email)
    try:
        bucket.set_iam_policy(policy)
        LOGGER.info("Added email {0} to the project {1} access list".format(
            email, project))
        return True
    except BadRequest: 
        LOGGER.info("There was an error on the request. The email {} was ignored.".format(
            email))
        return False

def upload_files(project):
    """
    Function to send files to a bucket. Gets a list of all the 
    files under the project root directory then it sends each file 
    one by one. The only way to know if the zip file is created is to 
    heck the compressed sotrage size. If the zip is created, then send it.
    """
    file_root = project.file_root()
    subfolders_fullpath = [x[0] for x in walk(file_root)]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(project.gcp.bucket_name)
    for indx, location in enumerate(subfolders_fullpath):
        chdir(location)
        files = [f for f in listdir('.') if path.isfile(f)]
        for file in files:
            temp_dir = location.replace(file_root,'')
            if temp_dir != '':
                blob = bucket.blob(path.join(temp_dir, file)[1:])
                blob.upload_from_filename(file)
            else:
                blob = bucket.blob(file)
                blob.upload_from_filename(file)
    if project.compressed_storage_size:
        zip_name = project.zip_name()
        chdir(project.project_file_root())
        blob = bucket.blob(zip_name)
        blob.upload_from_filename(zip_name)

############################################################
## Unused functions below this line, but usefull to have.
def set_bucket_permissions(bucket_name, email):
    """
    Function to set the permissions of a bucket to a specific group
    if ACL are used. At the moment we deal with bucket level permissions. 
    """
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    bucket.acl.group(email).grant_read()
    bucket.acl.save()

def list_bucket_permissions(bucket):
    """
    Function to list all the permissions of a bucket.
    """
    policy = bucket.get_iam_policy()
    for role in policy:
        members = policy[role]
        print('Role: {}, Members: {}'.format(role, members))


def create_directory_service(user_email, group=False):
    """Build and returns an Admin SDK Directory service object authorized with the service accounts
    that act on behalf of the given user.
    Args:
      user_email: The email of the user. Needs permissions to access the Admin APIs.
    Returns:
      Admin SDK directory service object.
    """
    logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
    credentials = ServiceAccountCredentials.from_p12_keyfile(
        settings.SERVICE_ACCOUNT_EMAIL,
        settings.SERVICE_ACCOUNT_PKCS12_FILE_PATH,
        settings.GCP_SECRET_KEY,
        scopes=['https://www.googleapis.com/auth/admin.directory.group',
                'https://www.googleapis.com/auth/apps.groups.settings'])
    # This requires the email used to delegate the credentials to the serivce account
    credentials = credentials.create_delegated(user_email)
    if group:
        return build('groupssettings', 'v1', credentials=credentials)
    return build('admin', 'directory_v1', credentials=credentials)

def paginate(request, to_paginate, maximun):
    """
    Function to paginate the arguments. 
    """
    page = request.GET.get('page', 1)
    paginator = Paginator(to_paginate, maximun)
    paginated = paginator.get_page(page)
    return paginated
