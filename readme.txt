Installed packages:

cryptography 38.0.1
dnspython    2.2.1

Usage instructions:

Part A - mydig

From command line args:
python main.py <Domain name> <DNS request type>

From input file:
Add your DNS queries to mydig_input.txt in the following format, each line is a separate query -

google.com A
example.com NS

Execute with:
python main.py

Output file - mydig_output.txt


Part B - mydig_dnssec

 From command line args:
python main_dnssec.py <Domain name> <DNS request type>

From input file:
Add your DNS queries to mydig_input_dnssec.txt in the following format, each line is a separate query -

google.com A
example.com NS

Execute with:
python main_dnssec.py

Output file - mydig_output.txt
