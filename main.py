import binascii
import socket
import dnslib
from dnslib import A

mult = '6d 75 6c 74 69 70 6c 79'


class DNS:
    PORT = 53
    IP = '127.0.0.1'

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.IP, self.PORT))

    def run(self):
        while True:
            try:
                message, address = self.socket.recvfrom(4096)
                response = DNSResolver().resolve(message)
                self.socket.sendto(response, address)
            except Exception as e:
                print("An error occurred:", str(e))


class DNSResolver:
    NAMESERVER = '198.41.0.4'

    def resolve(self, message):
        try:
            hex_message = binascii.hexlify(message).decode()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            hex_message_formatted = ExtraPoint().format_hex(hex_message[4:])
            addresses = [self.NAMESERVER]
            if mult in hex_message_formatted:
                return self.resolve_multiplication(sock, hex_message, hex_message_formatted)
            else:
                return self.resolve_dns(sock, hex_message, addresses)
        except Exception as e:
            print("An error occurred:", str(e))

    def resolve_multiplication(self, sock, hex_message, hex_message_formatted):
        multiple = ExtraPoint().multiply(hex_message_formatted.split(mult)[0])
        sock.sendto(binascii.unhexlify(hex_message), (self.NAMESERVER, DNS.PORT))
        response = sock.recvfrom(4096)[0]
        parsed_response = dnslib.DNSRecord.parse(response)
        answer = parsed_response.reply()
        question = str(answer.questions[0])
        id = question[1:question.rfind('.')]
        answer.add_answer(dnslib.RR(id, dnslib.QTYPE.A, rclass=dnslib.CLASS.IN, rdata=A(multiple)))
        sock.close()
        return answer.pack()

    def resolve_dns(self, sock, hex_message, addresses):
        while len(addresses) > 0:
            current_address = addresses.pop()
            sock.sendto(binascii.unhexlify(hex_message), (current_address, DNS.PORT))
            response = sock.recvfrom(4096)[0]
            parsed_response = dnslib.DNSRecord.parse(response)
            rcode = parsed_response.reply().header.rcode
            if parsed_response.a.rdata is not None or rcode != 0:
                return response
            if len(list(filter(lambda x: x.rtype == 1, parsed_response.ar))) > 0:
                for i in parsed_response.ar:
                    if i.rtype == 1:
                        addresses.append(str(i.rdata))
            elif len(parsed_response.auth) > 0:
                additional = str(parsed_response.auth[0].rdata)
                resp1 = self.resolve(dnslib.DNSRecord.question(additional).pack())
                parsed_resp1 = dnslib.DNSRecord.parse(resp1)
                if parsed_resp1.header.a == 0:
                    return response
                addresses.append(str(parsed_resp1.rr[0].rdata))
        error_record = dnslib.DNSRecord.parse(hex_message)
        error_record.header.rcode = 2
        print("я жив")
        return error_record.pack()


class ExtraPoint:
    def multiply(self, args):
        multiplication = 1
        numbers = args.split(' 00 00 00 00 00 01 01 ')[-1].split(' ')
        number = 0
        for i in numbers:
            if i == '08':
                multiplication = (multiplication * number) % 256
                break
            if i == '' or i[0] == '0':
                multiplication = (multiplication * number) % 256
                number = 0
                continue
            number = number * 10 + ord(i[1])
            if '0' <= i[1] <= '9':
                number -= 48
        return '127.0.0.' + str(multiplication)

    def format_hex(self, hex_string):
        octets = []
        for i in range(0, len(hex_string), 2):
            octets += [hex_string[i:i + 2]]
        pairs = []
        for i in range(0, len(octets), 2):
            pairs += [" ".join(octets[i:i + 2])]
        return " ".join(pairs)


def main():
    server = DNS()
    server.run()


if __name__ == "__main__":
    main()
