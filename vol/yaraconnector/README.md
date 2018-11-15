## YARACONNECTOR README ##
The connector uses the configured rules in the yara_rules directory to scan
binaries provided by Carbon Black. 

meta.score will be used to score binaries if provided , by default matching 
binareis will be given a score of 100.

To configure the connector, modify the yaraconnector.conf to supply the required
cbr AMQP and API credentials for retriviing binaries.
