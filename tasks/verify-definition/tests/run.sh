#!/usr/bin/env bash
# Copyright 2022 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

# source variables to test
ROOT=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

TASK_BUNDLE_REF="${TASK_BUNDLE_REF:-quay.io/hacbs-contract/ec-defintion-task-bundle:snapshot}"

TASKRUN=verify-definition-taskrun
TASKRUN_FILE="${TASKRUN}.yaml"
TASK_VERSION="${TASK_VERSION:-0.1}"
TASK_DIR="${ROOT}/../${TASK_VERSION}"
TEST_DIR="${TASK_DIR}/tests"

source ${ROOT}/../../helpers.sh

# run and wait for taskRun
TASK_RUN_NAME=$(TASK_BUNDLE_REF="${TASK_BUNDLE_REF}" envsubst < "${TEST_DIR}/${TASKRUN_FILE}" |kubectl create -o name -f -)

wait_for_taskrun
check_taskrun_status
