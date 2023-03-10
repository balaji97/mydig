import sys

import mydig
from models import Request

INPUT_FILENAME = "./mydig_input.txt"
OUTPUT_FILENAME = "./mydig_output.txt"

# Code for Part A
if __name__ == '__main__':
    output_lines = []

    if len(sys.argv) > 2:
        _, name, type = tuple(sys.argv)
        response = mydig.resolve_dns(
            Request(
                name=name,
                type=type
            )
        )
        output_lines.append(str(response))
    else:
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

    with open(OUTPUT_FILENAME, 'w') as output_file:
        for output_line in output_lines:
            output_file.write(output_line)
