#!/bin/bash -ex

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

apt-get update &

echo "Starting apps"
while true; do
    # Create default desktop shortcuts.
    mkdir -p ${HOME}/Desktop
    find /etc/skel/Desktop -name "*.desktop" -exec ln -sf {} ${HOME}/Desktop/ \; || true

    # Copy autostart shortcuts
    mkdir -p ${HOME}/.config/autostart
    find /etc/skel/Autostart -name "*.desktop" -exec ln -sf {} ${HOME}/.config/autostart/ \; || true

    eval ${ENTRYPOINT:-"xfce4-session"}
    sleep 5
done
