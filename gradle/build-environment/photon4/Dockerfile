# This dockerfile creates the cb enterprise build environment
ARG ARTIFACTORY_SERVER=artifactory-pub.bit9.local
ARG ARTIFACTORY_BASE_IMAGE=${ARTIFACTORY_SERVER}:5000/cb/connector_env_base:centos7-1.4.0
ARG BASE_IMAGE=photon4builder:latest
ARG BASE_IMAGE=${BASE_IMAGE:-ARTIFACTORY_BASE_IMAGE}
FROM ${BASE_IMAGE}

ARG ARTIFACTORY_SERVER
ENV ARTIFACTORY_SERVER=${ARTIFACTORY_SERVER}

ARG BASE_IMAGE
ENV BASE_IMAGE=${BASE_IMAGE}

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
