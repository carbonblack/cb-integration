Development Readme for CBSDK

Architecture:

By default, connectors are python programs.

Connectors run as their own pythonscript and report to supervisorD for control.

connectors live in vol/<connectorname> and use a .conf file for configuration.

The vol/<connectorname>/supervisord.conf may set up necessary background services
etc, as well as launch the connector itself under the control of supervisord 

The vol/<connectorname>/supervisordrpcinterface.py defines an rpcinteface 

The yara connector is a good example of a standard binary analysis connector.
