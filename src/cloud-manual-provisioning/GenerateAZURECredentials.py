#
# Copyright 2018-2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

"""License text"""

# This script is used to generate keys and CA certificates using openssl engine.
# The generated keys shall be available in azure directory
# These keys are used to provision to the secure element

import os
import sys
import logging
logging.basicConfig(format='%(message)s', level=logging.INFO)
log = logging.getLogger(__name__)
from Provision import GenerateAZURECredentials

def main():
    """
    This function generates key pair and certificates for AZURE cloud.
    :return: None
    """

    cur_dir = os.path.abspath(os.getcwd())
    GenerateAZURECredentials.generateCredentials(cur_dir)


if __name__ == "__main__":
    main()
