import inquirer
from jinja2 import Template

#
# Supervisord jinja2 template
#
supervisord_template = Template('''
[supervisord]
loglevel=debug                ; (log level;default info; others: debug,warn,trace)
nodaemon=true                ; (start in foreground if true;default false)

{% for connector in connectors %}
[program:{{connector}}]
directory=/samples/{{connector}}
command=python3 {{connector}}.py
user=root
autostart=true
autorestart=true
{% endfor %}
''')

nginx_template = Template('''

''')

def main():

    #
    # Figure out what connectors need to be started
    #
    questions = [
        inquirer.Checkbox('connectors',
                          message="What connectors would you like to include?",
                          choices=['yara', 'taxii']),
        inquirer.Text('cburl',
                      message="What is your Cb Response URL"),
        inquirer.Password('cbtoken',
                          message="What is your Cb Response api-key"),
    ]
    answers = inquirer.prompt(questions)

    connectors = answers.get("connectors",[])
    supervisord_conf = supervisord_template.render(
        connectors=connectors)

    cburl = answers.get('cburl', '')

    cbtoken = answers.get('cbtoken', '')

if __name__ == "__main__":
    print("Starting container build")
    main()
