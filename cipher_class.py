import string


class cipher_class:
    def ceaser(shift, text):
        char_list = list(text)
        new_list = []

        for i in char_list:
            if i in string.ascii_lowercase:
                new_list.append(string.ascii_lowercase[(string.ascii_lowercase.index(i) + int(shift)) % 26])
            elif i in string.ascii_uppercase:
                new_list.append(string.ascii_uppercase[(string.ascii_uppercase.index(i) + int(shift)) % 26])
            else:
                new_list.append(i)

        return ''.join(new_list)