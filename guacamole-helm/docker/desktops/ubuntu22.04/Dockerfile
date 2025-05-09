FROM ubuntu:jammy as ub

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN apt-get update && apt-get -y dist-upgrade &&  apt-get -y install fakeroot tzdata locales sudo dumb-init && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN ln -fs /usr/share/zoneinfo/Europe/Prague /etc/localtime && dpkg-reconfigure --frontend noninteractive tzdata && sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen && rm -f /usr/bin/sudo ; ln -s /usr/bin/fakeroot /usr/bin/sudo

RUN useradd --uid 1000 -s /bin/bash ubuntu && mkdir /home/ubuntu && cp -r /etc/skel/. /home/ubuntu && chown -R 1000:1000 /home/ubuntu

FROM scratch

COPY --chown=1000:1000 --from=ub / /

USER 1000

RUN mkdir -p /usr/share/glvnd/egl_vendor.d /usr/share/egl/egl_external_platform.d /etc/vulkan/implicit_layer.d /etc/vulkan/icd.d

WORKDIR /home/ubuntu

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN rm -f /usr/bin/chfn && ln -s /bin/true /usr/bin/chfn


RUN fakeroot apt-get update && DEBIAN_FRONTEND=noninteractive fakeroot apt-get install -y --no-install-recommends \
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
        curl \
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

COPY --chown=1000:1000 krb5.conf /etc/

RUN \
    mv /etc/xdg/autostart/xscreensaver.desktop /etc/xdg/autostart/xscreensaver.desktop.bak

COPY --chown=1000:1000 vulkan /usr/share/vulkan

ENV CONDA_DIR=/opt/conda \
    SHELL=/bin/bash \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8

ENV PATH="/opt/conda/bin:${PATH}"

ENV CONDA_MIRROR=https://github.com/conda-forge/miniforge/releases/latest/download

RUN set -x && cd /tmp && \
    miniforge_arch=$(uname -m) && \
    miniforge_installer="Miniforge3-Linux-${miniforge_arch}.sh" && \
    wget --quiet "${CONDA_MIRROR}/${miniforge_installer}" && \
    /bin/bash "${miniforge_installer}" -f -b -p "${CONDA_DIR}" && \
    rm "${miniforge_installer}" && \
    conda config --system --set auto_update_conda false && \
    conda config --system --set show_channel_urls true && conda init && rm -rf ~/.cache

# Set the DISPLAY variable.
ENV DISPLAY :0

ENV SDL_AUDIODRIVER pulse

# Set the PATH

COPY --chown=1000:1000  desktop-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create and set permissions for the user home directory
RUN mkdir -p /home/user && \
    # Create basic config files
    mkdir -p /home/user/.config /home/user/.local/share && \
    echo 'export PATH=$PATH:/home/user/.local/bin' > /home/user/.bashrc && \
    echo 'alias ll="ls -la"' >> /home/user/.bashrc && \
    # Set correct ownership
    chown -R 1000:1000 /home/user && \
    chmod -R 755 /home/user

WORKDIR /home/ubuntu

ENTRYPOINT ["/entrypoint.sh"]
