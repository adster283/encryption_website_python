from random import choice


class generator_func:
    
    def generator(selected_option, checked_num, checked_char, checked_low, checked_up, checked_sym, checked_amb):
        
        # lists of characters to be used in password
        nums = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
        symbols = ["!","@","#","$","%","^","&","*","_","-","+","=",";",":","?"]
        lower_case = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o", "p","q","r","s","t","u","v","w","x","y","z"]
        upper_case = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O", "P","Q","R","S","T","U","V","W","X","Y","Z"]
        ambiguous = ["{","}","[","]","(",")","/","'","`",",",".","<",">"]

        char_list = []

        # checking what characters to use in password
        if checked_num == "on":
            char_list.extend(nums)
        if checked_char == "on":
            char_list.extend(symbols)
        if checked_low == "on":
            char_list.extend(lower_case)
        if checked_up == "on":
            char_list.extend(upper_case)
        if checked_sym == "on":
            char_list.extend(ambiguous)
        if checked_amb == "on":
            char_list.extend(ambiguous)
        
        password = ""

        length = 0

        # checking what length to use in password
        # had to do this way as I could not get the value from the form to be an int
        if selected_option == "8":
            length = 8
        elif selected_option == "16":
            length = 16
        elif selected_option == "32":
            length = 32
        elif selected_option == "64":
            length = 64
        elif selected_option == "128":
            length = 128
        elif selected_option == "256":
            length = 256

        # generating password
        for i in range(length):
            password += choice(char_list)

        return password
        