from mydig import resolve_dns
from models import Request

INPUT_FILENAME = "./mydig_input.txt"
OUTPUT_FILENAME = "./mydig_output.txt"

if __name__ == '__main__':
    output_lines = []

    with open(INPUT_FILENAME, 'r') as input_file:
        for query in input_file.readlines():
            url, type = tuple(query.rstrip('\n').split(" "))
            response = resolve_dns(
                Request(
                    name=url,
                    type=type
                )
            )

            output_lines.append(str(response))

    with open(OUTPUT_FILENAME, 'w') as output_file:
        for output_line in output_lines:
            output_file.write(output_line)
