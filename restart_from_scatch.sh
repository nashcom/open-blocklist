#!/bin/bash
############################################################################
# Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
############################################################################

docker compose down
docker volume rm open-blocklist_open-blocklist-etcd-data
docker compose up 
