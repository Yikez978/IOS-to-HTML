#!/usr/bin/env python

from ciscoconfparse import CiscoConfParse
import re
from pprint import pprint
import markdown


def read_in_file(filename):
    return CiscoConfParse(filename)


def generate_pointee_markdown(parsed_config, pointee_objects):

    pointee_types = ['access-list', 'ip access-list', 'interface',
                     'route-map', 'class-map', 'policy-map']
    for pointee_type in pointee_types:
        for pointee in pointee_objects:
            for line in parsed_config.find_objects(r'.*'):
                if re.search(r'^' + pointee_type, line.text):
                    # markdown line to bold, hyperlink the name
                    new_line = line.text
                    new_line = re.sub(r'.*', '[' + pointee[1] + '] ' + '**' + new_line + '**', new_line)
                    new_line = re.sub(' ' + pointee[1] + r'( |$)', '*' + pointee[1] + '*' , new_line)
                    print new_line




def find_pointees(parsed_config):

    # Find all pointee lines and returns list lists.
    # The nested list object is a ciscoconfparse line object.

    pointee_types = ['access-list', 'ip access-list', 'interface',
                     'route-map', 'class-map', 'policy-map']

    object_list = []
    for pointee_type in pointee_types:
        re_pattern = r'^' + pointee_type
        conf_lines = (parsed_config.find_objects(re_pattern))
        for line in conf_lines:
            object_list.append(find_pointee_names(line, pointee_type))
    return object_list


def find_pointee_names(line, pointee_type):

    # Extracts object name from config line text,
    # and returns tuple of (line object, object name)

    if pointee_type == 'access-list':
        try:
            pointee_name = re.search(r'^access-list (\S+) .+$',
                                     line.text).group(1)
        except:
            pointee_name = "FAIL"
        return (line, pointee_name)
    elif pointee_type == 'ip access-list':
        try:
            pointee_name = re.search(r'^ip access-list .+ (\S+)$',
                                     line.text).group(1)
        except:
            pointee_name = "FAIL"
        return (line, pointee_name)
    elif pointee_type == 'interface':
        try:
            pointee_name = re.search(r'^interface (\S+)$',
                                     line.text).group(1)
        except:
            pointee_name = "FAIL"
        return (line, pointee_name)
    elif pointee_type == 'route-map':
        try:
            pointee_name = re.search(r'^route-map (\S+).*$',
                                     line.text).group(1)
        except:
            pointee_name = "FAIL"
        return (line, pointee_name)
    elif pointee_type == 'class-map':
        try:
            pointee_name = re.search(r'^class-map.+ (\S+)$',
                                     line.text).group(1)
        except:
            pointee_name = "FAIL"
        return (line, pointee_name)
    elif pointee_type == 'policy-map':
        try:
            pointee_name = re.search(r'^policy-map (.+ )?(\S+)$',
                                     line.text).group(2)
        except:
            pointee_name = "FAIL"
        return (line, pointee_name)
    else:
        return (line, "END_FAIL")


def find_pointers(parsed_config):

    # Find all pointers based on pointer types
    # The nested list object is a ciscoconfparse line object.

    pointer_types = ['access-class', 'access-group', 'policy-map',
                     'match access-group']

    object_list = []
    for pointer_type in pointer_types:
        re_pattern = r'^' + pointer_type
        object_list.extend(parsed_config.find_objects(re_pattern))
    return object_list


def find_references(pointer_objects, pointee_objects):

    # Finds each pointer that points to a pointee object and returns a list
    # of tuples that contains
    # (pointer ciscoconfparse line obj, pointee ciscoconfparse line obj,
    # pointee name list).

    pointer_to_pointee_data = []
    for pointer in pointer_objects:
        pointee_name_list = []
        for pointee in pointee_objects:
            if re.search(r' ' + pointee[1] + r'( |$)', pointer.text):
                pointee_name_list.append(pointee[1])

        pointee_name_list = list(set(pointee_name_list))
        pointer_to_pointee_data.append((pointer, pointee_name_list))
        del pointee_name_list

    #pprint(pointer_to_pointee_data)
    return pointer_to_pointee_data


def main():
    filename = 'startup-config.txt'
    parsed_config = read_in_file(filename)

    pointee_objects = find_pointees(parsed_config)
    #pointer_objects = find_pointers(parsed_config)

    generate_pointee_markdown(parsed_config, pointee_objects)

if __name__ == '__main__':
    main()
