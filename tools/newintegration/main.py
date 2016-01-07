#!/usr/bin/env python

__author__ = 'jgarman'

from jinja2 import Template
import argparse
import sys
import subprocess
import traceback
import os
from attrdict import AttrDict
import random
import shutil


class ProjectCreationError(Exception):
    def __init__(self, message=None, extended_output=None):
        self.message=message
        self.extended_output = extended_output


def create_project(provider_name):
    r = AttrDict()
    r.provider_name = provider_name
    r.repository_name = "cb-%s-connector" % provider_name
    r.rpm_name = "python-%s" % r.repository_name
    r.package_name = 'cbopensource.connectors.%s' % r.provider_name
    # by default there is one script
    r.scripts = [r.repository_name]

    # create a random port number for the listener
    r.port_number = random.randint(2000, 8000)

    template_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'templates')

    # create an empty git repository
    output = None
    if os.path.exists(r.repository_name):
        raise ProjectCreationError(message="Directory %s already exists" % r.repository_name)

    try:
        os.mkdir(r.repository_name, 0755)
    except OSError as e:
        raise ProjectCreationError(message="Could not create directory %s" % r.repository_name,
                                   extended_output=e)

    os.chdir(r.repository_name)

    try:
        output = subprocess.check_output("git init", shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise ProjectCreationError(message="Could not run git init on new repository",
                                   extended_output=output)

    # now cycle through the templates
    for root, _, files in os.walk(template_directory):
        reldir = os.path.relpath(root, template_directory)
        reldir = Template(reldir).render(**r)
        if not os.path.isdir(reldir):
            os.makedirs(reldir, 0755)

        for fn in files:
            destination_filename = fn.replace(".template", "")
            destination_filename = Template(destination_filename).render(**r)
            destination_file = os.path.join(reldir, destination_filename)
            source_template = os.path.join(root, fn)

            print "creating %s" % destination_file

            if fn.endswith(".template"):
                try:
                    t = Template(open(source_template, 'rb').read())
                    open(destination_file, 'wb').write(t.render(**r))
                    shutil.copymode(source_template, destination_file)
                except IOError as e:
                    raise ProjectCreationError(message="Could not create file %s from template %s" % (destination_file,
                                               source_template), extended_output=e.message)
            else:
                try:
                    shutil.copyfile(source_template, destination_file)
                except IOError as e:
                    raise ProjectCreationError(message="Could not copy file %s from %s" % (destination_file,
                                               source_template), extended_output=e.message)

    try:
        output = subprocess.check_output("git add .", shell=True, stderr=subprocess.STDOUT)
        output = subprocess.check_output("git commit -m 'Initial commit'", shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise ProjectCreationError(message="Could not run git commit on repository",
                                   extended_output=output)

    print "\nNew connector scaffolding created in %s." % r.repository_name
    print "Create a new repository on github.com and add the repository:"
    print "  git add remote origin git@github.com:carbonblack/%s.git" % r.repository_name
    print "  git push origin"


def main():
    parser = argparse.ArgumentParser(description="Create new Detonation provider")
    parser.add_argument("provider_name", help="Name of the detonation provider (for example: yara, cyphort, ...)")

    options = parser.parse_args()
    try:
        create_project(options.provider_name)
    except ProjectCreationError as e:
        sys.stderr.write("Could not create project %s: %s\n" % (options.provider_name, e.message))
        if e.extended_output:
            sys.stderr.write("More information:\n")
            for line in e.extended_output.split('\n'):
                sys.stderr.write("  %s\n" % line)

        return 1
    except Exception as e:
        sys.stderr.write("Unexpected error creating project %s: %s\n" % (options.provider_name, e))
        sys.stderr.write(traceback.format_exc() + '\n')

        return 2


if __name__ == '__main__':
    sys.exit(main())