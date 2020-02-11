### 1. STAGE (BUILD)
# Ubuntu 16.04 LTS with Baseimage and Runit
FROM phusion/baseimage:0.10.1 AS builder

# mapping core git branch
ARG MAPPING_CORE_VERSION=master

WORKDIR /app

# copy files
COPY cmake mapping-natur40/cmake
COPY conf mapping-natur40/conf
COPY docker-files mapping-natur40/docker-files
COPY src mapping-natur40/src
COPY test mapping-natur40/test
COPY CMakeLists.txt mapping-natur40/CMakeLists.txt

# set terminal to noninteractive
ARG DEBIAN_FRONTEND=noninteractive

# update packages and upgrade system
RUN apt-get update && \
    apt-get upgrade --yes -o Dpkg::Options::="--force-confold"

# install git and grab mapping-core
RUN apt-get install --yes git && \
    git clone --depth 1 --branch $MAPPING_CORE_VERSION https://github.com/umr-dbs/mapping-core.git

# install OpenCL
RUN chmod +x mapping-core/docker-files/install-opencl-build.sh && \
    mapping-core/docker-files/install-opencl-build.sh

# install MAPPING dependencies
RUN chmod +x mapping-core/docker-files/ppas.sh && \
    mapping-core/docker-files/ppas.sh && \
    python3 mapping-core/docker-files/read_dependencies.py mapping-core/docker-files/dependencies.csv "build dependencies" \
        | xargs -d '\n' -- apt-get install --yes

# install MAPPING Natur 4.0 dependencies
RUN python3 mapping-core/docker-files/read_dependencies.py mapping-natur40/docker-files/dependencies.csv "build dependencies" \
        | xargs -d '\n' -- apt-get install --yes

# Build MAPPING
RUN cd mapping-core && \
    cmake -DCMAKE_BUILD_TYPE=Release -DMAPPING_MODULES=mapping-natur40 . && \
    make -j$(cat /proc/cpuinfo | grep processor | wc -l)


### 2. STAGE (RUNTIME)
# Ubuntu 16.04 LTS with Baseimage and Runit
FROM phusion/baseimage:0.10.1

WORKDIR /app

COPY --from=builder /app/mapping-core/target/bin /app
COPY --from=builder \
    /app/mapping-core/docker-files \
    /app/mapping-natur40/docker-files \
    /app/docker-files/

# set terminal to noninteractive
ARG DEBIAN_FRONTEND=noninteractive

RUN \
    # update packages and upgrade system
    apt-get update && \
    apt-get upgrade --yes -o Dpkg::Options::="--force-confold" && \
    # install OpenCL
    chmod +x docker-files/install-opencl-runtime.sh && \
    docker-files/install-opencl-runtime.sh && \
    # install MAPPING dependencies
    chmod +x docker-files/ppas.sh && \
    docker-files/ppas.sh && \
    python3 docker-files/read_dependencies.py docker-files/dependencies.csv "runtime dependencies" \
        | xargs -d '\n' -- apt-get install --yes && \
    # install MAPPING Natur 4.0 dependencies
    python3 docker-files/read_dependencies.py docker-files/natur40-dependencies.csv "runtime dependencies" \
            | xargs -d '\n' -- apt-get install --yes && \
    # Make mountable files and give rights to www-data
    chown www-data:www-data . && \
    touch userdb.sqlite && \
    chown www-data:www-data userdb.sqlite && \
    mkdir rastersources && \
    chown www-data:www-data rastersources && \
    mkdir gdalsources_data && \
    chown www-data:www-data gdalsources_data && \
    mkdir gdalsources_description && \
    chown www-data:www-data gdalsources_description && \
    mkdir ogrsources_data && \
    chown www-data:www-data ogrsources_data && \
    mkdir ogrsources_description && \
    chown www-data:www-data ogrsources_description && \
    # Copy default config
    cp docker-files/settings.toml /etc/mapping.conf && \
    # module mounts
    mkdir abcd_files && \
    chown www-data:www-data abcd_files && \
    # Make service available
    mkdir --parents /etc/service/mapping/ && \
    mv docker-files/mapping-service.sh /etc/service/mapping/run && \
    chmod +x /etc/service/mapping/run && \
    ln -sfT /dev/stderr /var/log/mapping.log && \
    # Serve through apache httpd
    apt-get install --yes apache2 && \
    a2enmod proxy_fcgi && \
    awk '{ if ($0 == "</VirtualHost>") print "\n\tProxyPass /cgi-bin/mapping_cgi fcgi://localhost:10100\n</VirtualHost>"; else print $0}' \
        /etc/apache2/sites-enabled/000-default.conf > /etc/apache2/sites-enabled/tmp.conf && \
    mv -f /etc/apache2/sites-enabled/tmp.conf /etc/apache2/sites-enabled/000-default.conf && \
    # service apache2 restart && \
    mkdir --parents /etc/service/apache/ && \
        echo "#!/bin/sh\n\
\n\
set -e\n\
\n\
. /etc/apache2/envvars\
\n\
exec /usr/sbin/apache2 -f /etc/apache2/apache2.conf -DNO_DETACH 2>&1\n\
    " > /etc/service/apache/run && \
    mkdir /var/lock/apache2 && \
    mkdir /var/run/apache2 && \
    chmod +x /etc/service/apache/run && \
    ln -sfT /dev/stdout /var/log/apache2/access.log && \
    ln -sfT /dev/stderr /var/log/apache2/error.log && \
    # Clean APT and install scripts
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /app/docker-files

# Make port 10100 available to the world outside this container
# EXPOSE 10100
EXPOSE 80

# Expose mountable volumes
VOLUME /app/rastersources \
       /app/gdalsources_data \
       /app/gdalsources_description \
       # /app/userdb.sqlite \
       # /app/conf/settings.toml \
       /app/ogrsources_data \
       /app/ogrsources_description \
       # module mounts
       /app/abcd_files

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]
