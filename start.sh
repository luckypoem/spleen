#!/bin/bash

sudo mkdir -p /root/spleen/
sudo cp spleen-server.service /etc/systemd/system/
sudo cp spleen-server /root/spleen/
sudo cp .server.json /root/spleen/
systemctl enable spleen-server
systemctl start spleen-server
systemctl status spleen-server -l

