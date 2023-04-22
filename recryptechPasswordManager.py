import csv, pyperclip, hashlib, random, colorama, base64, os, sys
from Crypto.Cipher import AES
from Crypto import  Random

colorama.init()

def boot_program():
    class InvalidMenuChoice(Exception):
        """Raised when the option chosen is out of range"""
        pass

    def menu_line(line_length):
        for i in range(line_length): print(colorama.Style.BRIGHT + "\u2500" + colorama.Style.RESET_ALL, end="")
        print()

    def header():
        # Top Line
        menu_line(40)
        # Welcome
        print(" Welcome to the password manager... ".center(40))
        # Bottom Line
        menu_line(40)
        print()

    def master_password():
        data = ""
        try:
            with open("recryptechPasswordManagerPasswords.csv", "r") as entries:
                for line in entries:
                    data += line

                hashedMasterPass = data.split("\n")[0]
                access = False
                while not access:
                    masterPasswordGuess = input("Please enter the master password to continue: ".center(40))
                    hashedMasterPasswordGuess = hashlib.sha256(masterPasswordGuess.encode("utf-8")).hexdigest()
                    if hashedMasterPasswordGuess == hashedMasterPass:
                        access = True
                        print()
                        masterPassword = masterPasswordGuess
                        os.system("cls")
                        return masterPassword

                    else:
                        print("Incorrect. Please try again.")
                        print()

        # If there is no file, a master password needs to be created
        except FileNotFoundError:
            createNewMasterPass = True
            while createNewMasterPass:
                menu_line(40)
                masterPassword = input("Please create a master password: ")
                confirmMasterPass = input("Please retype the master password: ")
                menu_line(40)

                # If the attempts are the same
                if masterPassword == confirmMasterPass:
                    createNewMasterPass = False

                    # Hash and store the master password
                    hashedMasterPass = hashlib.sha256(masterPassword.encode("utf-8")).hexdigest()

                    with open("recryptechPasswordManagerPasswords.csv", "w+", newline="") as passwordsFile:
                        writer = csv.writer(passwordsFile, lineterminator="")
                        writer.writerow([hashedMasterPass])

                    # Let user know
                    os.system("cls")
                    print(f"The master password was saved.")
                    print(colorama.Fore.RED + "Please remember this password for future use." + colorama.Style.RESET_ALL)
                    print()
                    return masterPassword

                # If the attempts are not the same
                else:
                    print("The passwords were not the same, please retry...")

    def encrypt(plain_text, encryption_key):
        BLOCK_SIZE = 16
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

        private_key = hashlib.sha256(encryption_key.encode("utf-8")).digest()
        raw = pad(plain_text)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(private_key, AES.MODE_CBC, iv)

        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(encrypted_text, decryption_key):
        encrypted_text = encrypted_text[2: (len(encrypted_text)-1)]
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]

        private_key = hashlib.sha256(decryption_key.encode("utf-8")).digest()
        enc = base64.b64decode(encrypted_text)
        iv = enc[:16]
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        return (unpad(cipher.decrypt(enc[16:]))).decode("utf-8")

    # Display header
    header()

    # Ask and store master password
    masterPassword = master_password()

    def main_menu():
        # Ask question
        def menu_question():
            # Ask for user input
            try:
                choice = int(input("Please choose an option: "))
                if (choice > 7) or (choice < 1):
                    raise InvalidMenuChoice
            except ValueError:
                menu_line(40)
                print("There was an error. Please enter a number.")
                menu_line(40)
                print()
                return False
            except InvalidMenuChoice:
                menu_line(40)
                print("There was an error. Please choose a valid option.")
                menu_line(40)
                print()
                return False
            else:
                return choice

        # Print Menu
        menu_line(40)
        print("What would you like to do?".center(40))
        print("[Please choose 1-7]".center(40))

        #Print Choices
        menu_line(40)
        print("| 1 |" + colorama.Fore.GREEN + "View Entries".center(30) + colorama.Style.RESET_ALL)
        menu_line(40)
        print("| 2 |" + colorama.Fore.BLUE + "Generate Random Password".center(30) + colorama.Style.RESET_ALL)
        menu_line(40)
        print("| 3 |" + colorama.Fore.GREEN + "Add Entry".center(30) + colorama.Style.RESET_ALL)
        menu_line(40)
        print("| 4 |" + colorama.Fore.GREEN + "Edit Entries".center(30) + colorama.Style.RESET_ALL)
        menu_line(40)
        print("| 5 |" + colorama.Fore.RED + colorama.Style.BRIGHT + "Delete Entries".center(30) + colorama.Style.RESET_ALL)
        menu_line(40)
        print("| 6 |" + colorama.Fore.RED + "! Reset Program !".center(30) + colorama.Style.RESET_ALL)
        menu_line(40)
        print("| 7 |" + "Exit Program".center(30))
        menu_line(40)
        print()

        # Ask question until valid
        option = False
        while not option:
            option = menu_question()

        # Return user choice
        return option

    def website_menu(decryption_key):
        data = ""
        # If there are no entries, there will be an error. Catch and state
        try:
            with open("recryptechPasswordManagerPasswords.csv", "r") as entries:
                for line in entries:
                    data += line
            usersList = data.split("\n")
            del usersList[0]

            if not usersList:
                raise FileNotFoundError
        except FileNotFoundError:
            os.system("cls")
            menu_line(40)
            print("There are no entries to view".center(40))
            menu_line(40)
            print()
            main()

        # Print website menu

        for i in range(len(usersList)):
            userInfo = usersList[i].split(",")
            print(f"| {i+1} | {userInfo[0]}, {userInfo[1]}, ", end="")
            for j in range(len(decrypt(userInfo[2], decryption_key))): print("\u2022", end="")
            print()
            menu_line(40)
        print()

        return usersList

    def view_passwords(decryption_key):
        # Ask question
        def view_passwords_question():
            # Ask for user input
            choice = input(f"Please enter the name of the website to copy the password of: ")
            return choice

        print()
        menu_line(40)
        print("Viewing available entries..".center(40))
        menu_line(40)

        # Receive user list and print website menu
        usersList = website_menu(decryption_key)
        websites = []

        for i in range(len(usersList)):
            userInfo = usersList[i].split(",")
            websites += [userInfo[0]]

        # Ask question
        websiteToView = view_passwords_question()
        if websiteToView in websites:
            userInfo = usersList[websites.index(websiteToView)].split(",")

            passwordToCopy = (decrypt(userInfo[2], decryption_key)).strip()
            pyperclip.copy(passwordToCopy)
            os.system("cls")
            menu_line(40)
            print(f"The password for \"{websiteToView}\" has been copied to your clipboard.")
            menu_line(40)
            print()
            main()

        else:
            os.system("cls")
            menu_line(40)
            print(f"There is no entry for \"{websiteToView}.\"")
            menu_line(40)
            print()
            main()

    def generate_random_password():
        print()
        menu_line(40)
        print("Generate a random password...".center(40))
        menu_line(40)
        print("Security suggestions for " + colorama.Fore.GREEN + colorama.Style.BRIGHT + "good" + colorama.Style.RESET_ALL + " passwords:")
        print("- Should contain at least " + colorama.Style.BRIGHT + "15" + colorama.Style.RESET_ALL + " characters")
        print("- Should contain at least one " + colorama.Style.BRIGHT + "lowercase" + colorama.Style.RESET_ALL + " letter [a-z]")
        print("- Should contain at least one " + colorama.Style.BRIGHT + "uppercase" + colorama.Style.RESET_ALL + " letter [A-Z]")
        print("- Should contain at least one " + colorama.Style.BRIGHT + "number" + colorama.Style.RESET_ALL + " [0-9]")
        print("- Should contain at least one " + colorama.Style.BRIGHT + "symbol" + colorama.Style.RESET_ALL + " [?1*$...]")
        menu_line(40)

        letterCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercaseCharacters = "abcdefghijklmnopqrstuvwxyz"
        uppercaseCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        numberCharacters = "1234567890"
        symbolCharacters = "`~!@#$%^&*()_+-=[]{}\|;:'\",<.>?/"

        goodPassword = False
        while not goodPassword:
            try:
                print()
                passwordLength = int(input("Choose a length for the password: "))
                print()
                if passwordLength < 1:
                    raise ValueError
                if passwordLength < 15:
                    print(colorama.Fore.RED + "You have chosen to create a password less than 15 characters.")
                    print(colorama.Fore.RED + "This may risk the security of the created password.")
                    print(colorama.Style.RESET_ALL, end="")

                    goodAreYouSure = False
                    while not goodAreYouSure:
                        areYouSure = input("Would you like to proceed anyway? [Y/N]: ")
                        goodResponse = ["y", "n", "yes", "no"]
                        if areYouSure.lower() in goodResponse:
                            goodAreYouSure = True
                    if (areYouSure.lower() == "y") or (areYouSure.lower() == "yes"):
                        goodPassword = True
                    if (areYouSure.lower() == "n") or (areYouSure.lower() == "no"):
                        print()
                        os.system("cls")
                        main()
                if passwordLength > 255:
                    print("Woah! While a password this long may be strong, it's not practical!")
                else:
                    goodPassword = True
            except ValueError:
                pass

        randomPassword = ""
        numberOfEach = (passwordLength/4).__ceil__()
        randomPointer = []
        for i in range(numberOfEach):
            randomPointer += [1]
            randomPointer += [2]
            randomPointer += [3]
            randomPointer += [4]
        while len(randomPointer) != 0:
            chooseRandomType = random.randint(0,len(randomPointer) - 1)
            if randomPointer[chooseRandomType] == 1:
                randomPassword += lowercaseCharacters[random.randint(0,25)]
            elif randomPointer[chooseRandomType] == 2:
                randomPassword += uppercaseCharacters[random.randint(0, 25)]
            elif randomPointer[chooseRandomType] == 3:
                randomPassword += numberCharacters[random.randint(0, 9)]
            elif randomPointer[chooseRandomType] == 4:
                randomPassword += symbolCharacters[random.randint(0, 31)]
            del randomPointer[chooseRandomType]
        randomPasswordCharacterList = list(randomPassword)
        randomPasswordCharacterList[0] = letterCharacters[random.randint(0,50)]
        randomPasswordCharacterList[len(randomPassword) - 1] = letterCharacters[random.randint(0,50)]
        randomPassword = "".join(randomPasswordCharacterList)

        os.system("cls")
        menu_line(40)
        print(f"Random Password: {randomPassword}")
        pyperclip.copy(randomPassword)
        print("This password has been copied to your clipboard")
        menu_line(40)
        print()
        main()

    def add_passwords(encryption_key):
        print()
        menu_line(40)
        print("Add an entry...".center(40))
        menu_line(40)

        websiteName = input("Please enter the name of the website to add: ")
        userName = input("Please enter the username for the account: ")
        password = input("Please enter the password for the account: ")
        encryptedPassword = encrypt(password, encryption_key)

        userInfo = [websiteName, userName, encryptedPassword]

        with open("recryptechPasswordManagerPasswords.csv", "a+") as entries:
            writer = csv.writer(entries, lineterminator="")
            writer.writerow("\n")
            writer.writerow(userInfo)
        os.system("cls")
        menu_line(40)
        print(f"The entry for {websiteName} was added to your list.")
        menu_line(40)
        print()
        main()

    def edit_passwords(encryption_key):
        # Ask question
        def edit_passwords_question():
            # Ask for user input
            choice = input(f"Please enter the name of the website to edit the entry of: ")
            return choice

        print()
        menu_line(40)
        print("Edit an entry...".center(40))
        menu_line(40)

        data = ""
        with open("recryptechPasswordManagerPasswords.csv", "r") as entries:
            for line in entries:
                data += line
        data = data.split("\n")

        # Receive user list and print website menu
        usersList = website_menu(encryption_key)
        websites = []

        for i in range(len(usersList)):
            userInfo = usersList[i].split(",")
            websites += [userInfo[0]]

        websiteToView = edit_passwords_question()
        if websiteToView in websites:
            lineIndex = websites.index(websiteToView)

            goodAreYouSure = False
            while not goodAreYouSure:
                areYouSure = input(f"Are you sure you would like to edit the entry for \"{websiteToView}?\" [Y/N]: ")
                affirmativeResponse = ["y", "yes"]
                negativeResponse = ["n", "no"]
                if areYouSure.lower() in affirmativeResponse:

                    websiteName = input("Please enter the name for the website: ")
                    userName = input("Please enter the username for the account: ")
                    password = input("Please enter the password for the account: ")
                    hashedPassword = encrypt(password, encryption_key)

                    data[lineIndex + 1] = f"{websiteName},{userName},{hashedPassword}"

                    with open("recryptechPasswordManagerPasswords.csv", "w+", newline="") as entries:
                        writer = csv.writer(entries, lineterminator="")
                        for i in range(len(data)):
                            thisRow = data[i].split(",")
                            writer.writerow(thisRow)
                            if i != len(data) - 1:
                                writer.writerow("\n")
                    os.system("cls")
                    menu_line(40)
                    print(f"The entry for \"{websiteToView}\" has been edited.")
                    menu_line(40)
                    print()
                    main()
                elif areYouSure.lower() in negativeResponse:
                    print()
                    os.system("cls")
                    main()
        else:
            os.system("cls")
            menu_line(40)
            print(f"There is no entry for \"{websiteToView}.\"")
            menu_line(40)
            print()
            main()

    def delete_passwords(decryption_key):
        # Ask question
        def delete_passwords_question():
            # Ask for user input
            choice = input(f"Please enter the name of the website to delete the entry of: ")
            return choice

        print()
        menu_line(40)
        print("Delete an entry...".center(40))
        menu_line(40)

        data = ""
        with open("recryptechPasswordManagerPasswords.csv", "r") as entries:
            for line in entries:
                data += line
        data = data.split("\n")

        # Receive user list and print website menu
        usersList = website_menu(decryption_key)
        websites = []

        for i in range(len(usersList)):
            userInfo = usersList[i].split(",")
            websites += [userInfo[0]]

        websiteToView = delete_passwords_question()
        if websiteToView in websites:
            lineIndex = websites.index(websiteToView)

            goodAreYouSure = False
            while not goodAreYouSure:
                areYouSure = input(f"Are you sure you would like to delete the entry for \"{websiteToView}?\" [Y/N]: ")
                affirmativeResponse = ["y", "yes"]
                negativeResponse = ["n", "no"]
                if areYouSure.lower() in affirmativeResponse:

                    del data[lineIndex + 1]

                    with open("recryptechPasswordManagerPasswords.csv", "w+", newline="") as entries:
                        writer = csv.writer(entries, lineterminator="")
                        for i in range(len(data)):
                            thisRow = data[i].split(",")
                            writer.writerow(thisRow)
                            if i != len(data) - 1:
                                writer.writerow("\n")
                    os.system("cls")
                    menu_line(40)
                    print(f"The entry for \"{websiteToView}\" has been deleted.")
                    menu_line(40)
                    print()
                    main()
                elif areYouSure.lower() in negativeResponse:
                    print()
                    os.system("cls")
                    main()
        else:
            os.system("cls")
            print(f"There is no entry for \"{websiteToView}.\"")
            print()
            main()

    def reset_program():
        affirmativeResponse = ["y", "yes"]
        areYouSure = input(colorama.Fore.RED + "Are you sure you would like to reset this program? [Y/N]: " + colorama.Style.RESET_ALL)
        if areYouSure in affirmativeResponse:
            areYouSure = input(colorama.Fore.RED + colorama.Style.BRIGHT + "Are you really sure you would like to reset this program? This will delete all passwords and master password [Y/N]: " + colorama.Style.RESET_ALL)

        if (os.path.exists("recryptechPasswordManagerPasswords.csv")) and (areYouSure in affirmativeResponse):
            os.remove("recryptechPasswordManagerPasswords.csv")
            print()
            os.system("cls")
            boot_program()
        elif not (os.path.exists("recryptechPasswordManagerPasswords.csv")):
            os.system("cls")
            menu_line(40)
            print("The file does not exist. The program will be reset.")
            menu_line(40)
            print()
            boot_program()
        else:
            print()
            os.system("cls")
            main()

    def main():
        # Ask for the user's choice
        choice = main_menu()

        # Determine which menu to use
        if choice == 1:
            view_passwords(masterPassword)
        elif choice == 2:
            generate_random_password()
        elif choice == 3:
            add_passwords(masterPassword)
        elif choice == 4:
            edit_passwords(masterPassword)
        elif choice == 5:
            delete_passwords(masterPassword)
        elif choice == 6:
            reset_program()
        elif choice == 7:
            sys.exit()

    # Run program
    main()

#Initial boot program
boot_program()