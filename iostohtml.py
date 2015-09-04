#!/usr/bin/env python

from ciscoconfparse import CiscoConfParse
import re


def read_in_file(filename):
    return CiscoConfParse(filename)


def find_acls(parsed_config):

    acl_names = []

    # Get standard ACL numbers/names
    standard_acls = parsed_config.find_objects('^access-list')
    for acl in standard_acls:
        try:
            acl_names.append(re.search(r'^access-list (\S+)',
                                       acl.text).group(1))
        except:
            pass

    # Get extended ACL names
    acls = parsed_config.find_objects('^ip access-list')
    for acl in acls:
        try:
            acl_names.append(re.search(r'^ip access-list .+ (\S+)$',
                                       acl.text).group(1))
        except:
            pass
    unique_acls = set(acl_names)

    return unique_acls


def find_class_maps(parsed_config):

    # Get class-map names
    cmaps = []

    class_map_ojbs = parsed_config.find_objects('^class-map')

    for cmap in class_map_ojbs:
        try:
            cmaps.append(re.search(r'^class-map.+ (\S+)$',
                                   cmap.text).group(1))
        except:
            pass
    return set(cmaps)


def find_policy_maps(parsed_config):

    # Get policy-map names
    pmaps = []

    pmap_objs = parsed_config.find_objects('^policy-map')

    for pmap in pmap_objs:
        try:
            pmaps.append(re.search(r'^policy-map .+ (\S+)$',
                                   pmap.text).group(1))
        except:
            pass
    return set(pmaps)


def find_route_maps(parsed_config):

    # Get route-map names
    rmaps = []

    rmap_objs = parsed_config.find_objects('^route-map')

    for rmap in rmap_objs:
        try:
            rmaps.append(re.search(r'^route-map (\S+).*$',
                                   rmap.text).group(1))
        except:
            pass
    return set(rmaps)


def find_interfaces(parsed_config):

    # Get interface names
    intfs = []

    intf_objs = parsed_config.find_objects('^interface')

    for intf in intf_objs:
        try:
            intfs.append(re.search(r'^interface (\S+)$',
                                   intf.text).group(1))
        except:
            pass
    return set(intfs)


def find_pointers_to_acls(parsed_config, acls):

    valid_pointers = ['ip access-group']
    real_pointers = []

    for acl in acls:
        # find each line where there is a valid pointer.
        # Capture the pointer line text, pointer name, and the pointee name
        



def main():
    filename = 'startup-config.txt'
    parsed_config = read_in_file(filename)

    acls = find_acls(parsed_config)
    for acl in acls:
        print acl

    print '--------------------'

    cmaps = find_class_maps(parsed_config)
    for cmap in cmaps:
        print cmap

    print '--------------------'

    pmaps = find_policy_maps(parsed_config)
    for pmap in pmaps:
        print pmap
    print '--------------------'

    rmaps = find_route_maps(parsed_config)
    for rmap in rmaps:
        print rmap

    print '--------------------'

    intfs = find_interfaces(parsed_config)
    for intf in intfs:
        print intf


if __name__ == '__main__':
    main()
