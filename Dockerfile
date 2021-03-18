FROM python:3.9.2-slim

# Install security updates, make, gcc and clang
RUN apt-get update && \
    apt-get -y upgrade && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install make gcc clang && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create a user that has the same GID and UID as you
ARG GROUP_ID
ARG USER_ID
RUN groupadd -g $GROUP_ID dis-cover
RUN useradd -m -r -u $USER_ID -g $GROUP_ID dis-cover

# Work directory
WORKDIR /home/dis-cover/dis-cover

# Install python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Create a symbolic link to have access to the dis-cover command
RUN ln -s /home/dis-cover/dis-cover/dis-cover/__main__.py /bin/dis-cover

# Use the dis-cover user
USER dis-cover
