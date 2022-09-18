import dnssec_validation
import mydig
import mydig_dnssec
from models import Request

INPUT_FILENAME = "./mydig_input.txt"
OUTPUT_FILENAME = "./mydig_output.txt"
OUTPUT_FILENAME_DNSSEC = "./mydig_output_dnssec.txt"

if __name__ == '__main__':
    # Initialize libraries
    dnssec_validation.__init__()

    output_lines = []
    output_lines_dnssec = []

    with open(INPUT_FILENAME, 'r') as input_file:
        for query in input_file.readlines():
            url, type = tuple(query.rstrip('\n').split(" "))
            response = mydig.resolve_dns(
                Request(
                    name=url,
                    type=type
                )
            )
            output_lines.append(str(response))

            response_dnssec = mydig_dnssec.resolve_dns(Request(
                name=url,
                type=type
            ))
            output_lines_dnssec.append(str(response_dnssec))

    with open(OUTPUT_FILENAME, 'w') as output_file:
        for output_line in output_lines:
            output_file.write(output_line)

    with open(OUTPUT_FILENAME_DNSSEC, 'w') as output_file:
        for output_line in output_lines_dnssec:
            output_file.write(output_line)
