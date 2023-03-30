ARG VARIANT=3.7
FROM python:${VARIANT}

ARG USERNAME=niceuser
ARG USER_UID=1000
ARG USER_GID=$USER_UID

USER root
RUN apt update \
    && export DEBIAN_FRONTEND=noninteractive \
    && LANG=C LC_ALL=C apt-get -y install --no-install-recommends \    
    plantuml \
    pandoc \
    vim \
    sudo \
    gdb \
    && groupadd --gid $USER_GID $USERNAME \
    && useradd -s /bin/bash --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME\
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

USER ${USERNAME}
WORKDIR /workspace
COPY requirements.txt /tmp
ENV PATH "$PATH:/home/${USERNAME}/.local/bin"
RUN python -m pip install --upgrade pip wheel setuptools \
    && python -m pip install build tox==4.3.5 \
    pytest pytest-cov pytest-html pytest-mock -r/tmp/requirements.txt
