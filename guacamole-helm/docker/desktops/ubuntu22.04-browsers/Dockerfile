FROM cerit.io/os/ubuntu:22.04-user

RUN rm -f /usr/bin/chfn && ln -s /bin/true /usr/bin/chfn

# Prevent snapd installation
RUN echo 'Package: snapd\nPin: release a=*\nPin-Priority: -10\n' > /etc/apt/preferences.d/no-snapd

# Install basic tools needed for apt operations
RUN fakeroot apt-get update && DEBIAN_FRONTEND=noninteractive fakeroot apt-get install -y --no-install-recommends \
    gnupg \
    software-properties-common \
    curl \
    apt-transport-https \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Setup Firefox from Mozilla Team PPA (non-snap version)
RUN fakeroot apt-get update && \
    DEBIAN_FRONTEND=noninteractive fakeroot add-apt-repository -y ppa:mozillateam/ppa && \
    echo "Package: firefox*\nPin: release o=LP-PPA-mozillateam\nPin-Priority: 1001" | tee /etc/apt/preferences.d/mozilla-firefox \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Firefox first as it's potentially troublesome
RUN fakeroot apt-get update && DEBIAN_FRONTEND=noninteractive fakeroot apt-get install -y --no-install-recommends --no-install-suggests \
    firefox \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Google Chrome
RUN cd /tmp/ && curl -sfLO https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && fakeroot dpkg -i google-chrome-stable_current_amd64.deb || true && \
    fakeroot apt-get update && fakeroot apt-get -f install -y && rm -f /tmp/google-chrome-stable_current_amd64.deb \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install main packages
RUN fakeroot apt-get update && DEBIAN_FRONTEND=noninteractive fakeroot apt-get install -y --no-install-recommends --no-install-suggests \
        libxcb-keysyms1 \
        xfce4 \
        xfce4-terminal \
        xfce4-pulseaudio-plugin \
        xfce4-whiskermenu-plugin \
        terminator \
        mesa-utils \
        mesa-utils-extra \
        x11-xserver-utils \
        x11-utils \
        libxrandr-dev \
        vim \
        nano \
        mc \
        gnupg2 \
        less \
        ca-certificates \
        fonts-liberation \
        libnspr4 \
        libnss3 \
        wget \
        xdg-utils \
        xinput \
        xfce4-xkb-plugin \
        dbus-x11 \
        adwaita-icon-theme-full \
        ssh rsync \
        xfce4-power-manager gvfs xfce4-notifyd tango-icon-theme desktop-base xubuntu-icon-theme greybird-gtk-theme xdg-user-dirs libasound2 krb5-user mesa-vulkan-drivers vulkan-tools s4cmd at-spi2-core pavucontrol \
        perl unzip file rar ruby zip bzip2 lzop p7zip-full \
        gnome-icon-theme xfonts-terminus fonts-ubuntu fonts-freefont-ttf fonts-freefont-otf fonts-dejavu-core fonts-dejavu-extra fonts-droid-fallback\
        && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN echo "alias apt-get='fakeroot apt-get'" >> /etc/bash.bashrc &&  echo "alias apt='fakeroot apt'" >> /etc/bash.bashrc && echo "alias dpkg='fakeroot dpkg'" >> /etc/bash.bashrc
# Set the DISPLAY variable.
ENV DISPLAY=:0

ENV SDL_AUDIODRIVER=pulse
ENV CONDA_DIR=/opt/conda \
    SHELL=/bin/bash \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8

ENV PATH="/opt/conda/bin:${PATH}"

# Install Miniforge (conda) with direct URL and better error handling
RUN set -x && cd /tmp && \
    miniforge_arch=$(uname -m) && \
    wget --tries=3 --timeout=15 --no-verbose "https://github.com/conda-forge/miniforge/releases/download/23.3.1-1/Mambaforge-23.3.1-1-Linux-$(uname -m).sh" -O miniforge.sh && \
    chmod +x miniforge.sh && \
    bash miniforge.sh -f -b -p "${CONDA_DIR}" && \
    rm miniforge.sh && \
    if [ -d "${CONDA_DIR}" ]; then \
        ${CONDA_DIR}/bin/conda config --system --set auto_update_conda false && \
        ${CONDA_DIR}/bin/conda config --system --set show_channel_urls true && \
        ${CONDA_DIR}/bin/conda init bash; \
    fi && \
    rm -rf /root/.cache


# Copy entrypoint script and set permissions
COPY desktop-entrypoint.sh /entrypoint.sh

# Create and set permissions for the user home directory
RUN mkdir -p /home/user && \
    # Create basic config files
    mkdir -p /home/user/.config /home/user/.local/share && \
    echo 'export PATH=$PATH:/home/user/.local/bin' > /home/user/.bashrc && \
    echo 'alias ll="ls -la"' >> /home/user/.bashrc && \
    # Set correct ownership
    chown -R 1000:1000 /home/user && \
    chmod -R 755 /home/user

# Set the working directory to /home/ubuntu
WORKDIR /home/ubuntu

ENTRYPOINT ["/entrypoint.sh"]
