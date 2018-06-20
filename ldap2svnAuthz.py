#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Generates authz file for svn repo.
    inspired on whitlockjc's sync-ldap-groups-to-svn-authz.py
    added features:
    - pure unicode
    - external config.yaml
    - one-level groups traversal
    - switch to argparse (python 2.7+)

    NOTE: accesses are go under '/' svn path. There was no need in another paths.

"""
import ldsvtools.Config as Config
import ldsvtools.Authz as Authz

def main():
    """main func."""
    Config.load()
    Authz.load()
    Authz.save()


if __name__ == "__main__":
    main()
