# Custom Desktop Configurations

This directory contains Docker configurations for creating custom desktop environments that can be used with the Secure Desktop system. These desktop images are deployed as containers and made accessible through Apache Guacamole.

## Available Desktop Configurations

Currently, the following desktop configurations are provided:

- **ubuntu22.04**: A basic Ubuntu 22.04 desktop with XFCE4 and essential utilities.
- **ubuntu22.04-browsers**: Enhanced Ubuntu 22.04 desktop with Firefox and Google Chrome installed.

## Creating Your Own Desktop Configuration

You can create custom desktop configurations to meet specific needs. Here's how to build your own:

### Prerequisites

- Docker installed on your local machine for building images
- Access to a container registry to push your images (the registry must be public or accessible by your Rancher instance)

### Basic Structure

A desktop configuration typically includes:

1. **Dockerfile**: Defines the desktop environment and installed applications
2. **desktop-entrypoint.sh**: Script that initializes the desktop environment
3. **Supporting files**: Additional configuration files (like `krb5.conf`) or directories (like `vulkan/`)

### Step-by-Step Guide

1. **Create a new directory** for your desktop configuration:
   ```bash
   mkdir -p my-custom-desktop
   cd my-custom-desktop
   ```

2. **Create a Dockerfile** based on the existing examples:
   ```Dockerfile
   # Start with Ubuntu as the base image
   FROM ubuntu:jammy as ub

   # Set up environment variables, locales, and users
   ENV LANG en_US.UTF-8
   ENV LANGUAGE en_US:en
   ENV LC_ALL en_US.UTF-8

   # Install basic dependencies
   RUN apt-get update && apt-get -y dist-upgrade && \
       apt-get -y install fakeroot tzdata locales sudo dumb-init && \
       apt-get clean && rm -rf /var/lib/apt/lists/*

   # Set up locale and create non-root user
   RUN ln -fs /usr/share/zoneinfo/Europe/Prague /etc/localtime && \
       dpkg-reconfigure --frontend noninteractive tzdata && \
       sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
       locale-gen && rm -f /usr/bin/sudo ; ln -s /usr/bin/fakeroot /usr/bin/sudo

   RUN useradd --uid 1000 -s /bin/bash ubuntu && \
       mkdir /home/ubuntu && \
       cp -r /etc/skel/. /home/ubuntu && \
       chown -R 1000:1000 /home/ubuntu

   # Use scratch as the second stage to minimize layers
   FROM scratch

   # Copy everything from the first stage
   COPY --chown=1000:1000 --from=ub / /

   # Switch to non-root user
   USER 1000

   # Create directories required for graphics acceleration
   RUN mkdir -p /usr/share/glvnd/egl_vendor.d /usr/share/egl/egl_external_platform.d \
       /etc/vulkan/implicit_layer.d /etc/vulkan/icd.d

   # Set working directory
   WORKDIR /home/ubuntu

   # Set environment variables
   ENV LANG en_US.UTF-8
   ENV LANGUAGE en_US:en
   ENV LC_ALL en_US.UTF-8

   # Install desktop environment and applications
   RUN fakeroot apt-get update && DEBIAN_FRONTEND=noninteractive fakeroot apt-get install -y --no-install-recommends \
       xfce4 \
       xfce4-terminal \
       # Add your custom packages here \
       && apt-get clean && rm -rf /var/lib/apt/lists/*

   # Set up the entrypoint script
   COPY --chown=1000:1000 desktop-entrypoint.sh /entrypoint.sh
   RUN chmod +x /entrypoint.sh

   # Set display environment variables
   ENV DISPLAY :0

   ENTRYPOINT ["/entrypoint.sh"]
   ```

3. **Create an entrypoint script** (`desktop-entrypoint.sh`):
   ```bash
   #!/bin/bash -ex

   set +x
   echo "Waiting for X server"
   until [[ -e /var/run/appconfig/xserver_ready ]]; do sleep 1; done
   [[ -f /var/run/appconfig/.Xauthority ]] && cp /var/run/appconfig/.Xauthority ${HOME}/
   echo "X server is ready"
   set -x

   echo "Setting resolution"
   RESOLUTION=${RESOLUTION:-1920x1080}
   xrandr --fb ${RESOLUTION}
   xrandr -s ${RESOLUTION}

   xset m 1/15 10
   xset r rate 250 40

   echo "Starting apps"
   while true; do
       # Create default desktop shortcuts
       mkdir -p ${HOME}/Desktop
       find /etc/skel/Desktop -name "*.desktop" -exec ln -sf {} ${HOME}/Desktop/ \; || true

       # Copy autostart shortcuts
       mkdir -p ${HOME}/.config/autostart
       find /etc/skel/Autostart -name "*.desktop" -exec ln -sf {} ${HOME}/.config/autostart/ \; || true

       eval ${ENTRYPOINT:-"xfce4-session"}
       sleep 5
   done
   ```

4. **Build and test your image locally**:
   ```bash
   docker build -t my-custom-desktop:latest .
   ```

5. **Push the image to a container registry**:
   ```bash
   # Tag the image for your registry
   docker tag my-custom-desktop:latest your-registry.io/your-repo/my-custom-desktop:latest

   # Push to the registry
   docker push your-registry.io/your-repo/my-custom-desktop:latest
   ```

### Important Considerations

1. **Security**:
   - Always use a non-root user (UID 1000) for the desktop environment
   - Use a multi-stage build to minimize the attack surface
   - Consider using `fakeroot` for package management operations

2. **Registry Access**:
   - **IMPORTANT**: The container registry must be either public or the Rancher client must be authorized to pull from it

3. **Resources**:
   - Consider the resource requirements of your desktop (CPU, memory, disk)
   - Include only necessary applications to keep the image size manageable

4. **Customization**:
   - To add custom application launchers, place `.desktop` files in `/etc/skel/Desktop/`
   - For autostart applications, place `.desktop` files in `/etc/skel/Autostart/`

## Using Your Custom Desktop

Once you've created and pushed your custom desktop image, you can use it directly in the application:

1. **Access the Desktop Manager UI** as an admin in your browser
2. **Navigate to the desktop configuration tab**
3. **Enter the image name** of your custom desktop (e.g., `your-registry.io/your-repo/my-custom-desktop:latest`)
4. **Create or update a desktop** using your custom image

Rancher will pull the specified image from the registry when creating new desktop instances.

> **Note**: The container registry must be either public or the Rancher client must be authorized to pull from it.

## Example Customizations

### Adding Custom Software

To add custom software to your desktop image, modify the Dockerfile:

```Dockerfile
# Install additional software
RUN fakeroot apt-get update && DEBIAN_FRONTEND=noninteractive fakeroot apt-get install -y --no-install-recommends \
    gimp \
    inkscape \
    code \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
```

### Default Resolution

To change the default resolution, modify the `desktop-entrypoint.sh`:

```bash
# Set a different default resolution
RESOLUTION=${RESOLUTION:-2560x1440}
```

### Adding NVIDIA GPU Support

For GPU-accelerated desktops, check the `vulkan/` directory in the existing examples and include GPU-specific packages:

```Dockerfile
# Install NVIDIA support
RUN fakeroot apt-get update && DEBIAN_FRONTEND=noninteractive fakeroot apt-get install -y --no-install-recommends \
    nvidia-driver-xxx \
    nvidia-cuda-toolkit \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
```
