# Copyright The Enterprise Contract Contributors
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

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.3@sha256:bc552efb4966aaa44b02532be3168ac1ff18e2af299d0fe89502a1d9fabafbc5 AS downloads

ARG TARGETOS
ARG TARGETARCH

ARG COSIGN_VERSION

ADD https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${TARGETOS}-${TARGETARCH} /opt/
ADD https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign_checksums.txt /opt/

RUN cd /opt && \
    sha256sum --check <(grep -w "cosign-${TARGETOS}-${TARGETARCH}" < cosign_checksums.txt) && \
    mv cosign-$TARGETOS-$TARGETARCH cosign && \
    chmod +x cosign

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.3@sha256:bc552efb4966aaa44b02532be3168ac1ff18e2af299d0fe89502a1d9fabafbc5

ARG TARGETOS
ARG TARGETARCH

COPY --from=downloads /opt/cosign /usr/local/bin/
RUN cosign version

RUN microdnf -y install git-core jq && microdnf clean all

COPY "dist/ec_"$TARGETOS"_"$TARGETARCH /usr/bin/ec

ENTRYPOINT ["/usr/bin/ec"]
