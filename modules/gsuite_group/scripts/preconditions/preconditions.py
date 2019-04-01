#!/usr/bin/env python3

# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
import logging
import re
import sys
import os

try:
    import google.auth
    from google.oauth2 import service_account
    from googleapiclient import discovery, errors
except ImportError as e:
    if os.environ.get('GRACEFUL_IMPORTERROR', '') != '':
        sys.stderr.write("Unable to import Google API dependencies, skipping "
                         "GCP precondition checks!\n")
        sys.exit(0)
    else:
        raise e


class Requirements:
    def __init__(self, req_type, resource, required, provided):
        self.req_type = req_type
        self.resource = resource
        self.required = set(required)
        self.provided = set(provided)

    def is_satisfied(self):
        """
        Is this requirement satisfied?
        """
        return (self.required & self.provided) == self.required

    def satisfied(self):
        """
        Generate a list of requirements that have been satisfied. Resources
        that were provided but aren't required are not returned.
        """
        return list(self.required & self.provided)

    def unsatisfied(self):
        """
        Generate a list of requirements that have not been satisfied.
        """
        return list(self.required - self.provided)

    def asdict(self):
        return {
            "type": self.req_type,
            "name": self.resource,
            "satisfied": self.satisfied(),
            "unsatisfied": self.unsatisfied(),
        }


class OrgPermissions:
    # Permissions that the service account must have for any organization
    ALL_PERMISSIONS = [
        # Typically granted with `roles/resourcemanager.organizationViewer`
        "resourcemanager.organizations.get",
    ]

    def __init__(self, org_id):
        """
        Create a new organization validator.

        Args:
            org_id (str): The organization ID
        """
        self.org_id = org_id
        self.permissions = self.ALL_PERMISSIONS[:]

    def validate(self, credentials):
        service = discovery.build(
            'cloudresourcemanager', 'v1',
            credentials=credentials
        )

        body = {"permissions": self.permissions}
        resource = "organizations/" + self.org_id

        request = service.organizations().testIamPermissions(
            resource=resource,
            body=body)
        response = request.execute()

        req = Requirements(
            "Service account permissions on organization",
            resource,
            self.permissions,
            response.get("permissions", []),
        )

        return req.asdict()


def setup():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.WARN)

    cache_log = logging.getLogger('googleapiclient.discovery_cache')
    cache_log.setLevel(logging.ERROR)

    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def get_credentials(credentials_path):
    """Fetch credentials for verifying Project Factory preconditions.

    Credentials will be loaded from a service account file if present, or
    from Application Default Credentials otherwise.

    Args:
        credentials_path: an optional path to service account credentials.

    Returns:
        (credentials, project_id): A tuple containing the credentials and
        associated project ID.
    """
    if credentials_path is not None:
        # Prefer an explicit credentials file
        svc_credentials = service_account.Credentials\
            .from_service_account_file(credentials_path)
        credentials = (svc_credentials, svc_credentials.project_id)
    else:
        # Fall back to application default credentials
        try:
            credentials = google.auth.default()
        except google.auth.exceptions.RefreshError:
            raise google.auth.exceptions.DefaultCredentialsError()

    return credentials


class EmptyStrAction(argparse.Action):
    """
    Convert empty string values parsed by argparse into None.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        values = None if values == '' else values
        setattr(namespace, self.dest, values)


def argparser():
    parser = argparse.ArgumentParser(
        description="""Check that Project Factory preconditions are met on the
        provided service account, project parent, and billing account.
        """
    )

    parser.add_argument(
        '--verbose', required=False, default=False,
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--credentials_path', required=True, action=EmptyStrAction,
        help='The service account credentials to check'
    )
    parser.add_argument(
        '--org_id', required=True, action=EmptyStrAction,
        help='The organization ID'
    )
    parser.add_argument(
        '--domain', required=False, action=EmptyStrAction,
        help='The gsuite domain name'
    )

    return parser


def validators_for(opts, seed_project):
    """
    Given a set of CLI options, determine which preconditions we need
    to check and generate corresponding validators.
    """
    validators = []

    if opts.domain is None:
        validators.append(OrgPermissions(opts.org_id))

    return validators


def main(argv):
    try:
        opts = argparser().parse_args(argv[1:])
        (credentials, project_id) = get_credentials(opts.credentials_path)
        validators = validators_for(opts, project_id)

        results = []
        for validator in validators:
            results.append(validator.validate(credentials))

        retcode = 0
        for result in results:
            if len(result["unsatisfied"]) > 0:
                retcode = 1

        if retcode == 1 or opts.verbose:
            json.dump(results, sys.stdout, indent=4)
    except FileNotFoundError as error:  # noqa: F821
        print(error)
        retcode = 1

    return retcode


if __name__ == "__main__":
    setup()
    retcode = main(sys.argv)
    sys.exit(retcode)
