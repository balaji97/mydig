from mydig import resolve_dns
from models import Request

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    resolve_dns(
        Request(
            name="www.cnn.com",
            type="A"
        )
    )

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
