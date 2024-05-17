#
# Copyright 2018-2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

"""License text"""

# This script is used to provision key and certificate to secure element.
# These Provisioned keys and certificates are used in azure demo

import os
import sys
import logging

log = logging.getLogger(__name__)
logging.basicConfig(format='%(message)s', level=logging.INFO)
from Provision import ResetAndUpdate_AZURE

KEYPAIR_INDEX_CLIENT_PRIVATE = 0x83000001
CERTIFICATE_INDEX = 0x83000002


def main():
    """
    This function provision the generated key pair and certificates for AZURE cloud.
    :return: None
    """

    cur_dir = os.getcwd()
    ResetAndUpdate_AZURE.reset_and_update(cur_dir, KEYPAIR_INDEX_CLIENT_PRIVATE, CERTIFICATE_INDEX)


if __name__ == '__main__':
    main()
