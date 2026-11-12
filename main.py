"""Entry point: run with `python main.py`."""
from auth import login_user, register_user
from storage import initialize_project
from vault import decrypt_file, delete_file, encrypt_file, list_files


def main_menu(username, master_key):
    while True:
        print("\n" + "=" * 45)
        print(f"ENCRYPTED FILE VAULT — USER: {username}")
        print("=" * 45)
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. List encrypted files")
        print("4. Delete an encrypted file")
        print("5. Log out")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            encrypt_file(username, master_key)
        elif choice == "2":
            decrypt_file(username, master_key)
        elif choice == "3":
            list_files(username)
        elif choice == "4":
            delete_file(username)
        elif choice == "5":
            print("You have been logged out.")
            break
        else:
            print("Invalid option. Please choose 1-5.")


def main():
    initialize_project()

    while True:
        print("\n" + "=" * 35)
        print("WELCOME TO ENCRYPTED FILE VAULT")
        print("=" * 35)
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        try:
            if choice == "1":
                register_user()
            elif choice == "2":
                result = login_user()
                if result is not None:
                    username, master_key = result
                    main_menu(username, master_key)
            elif choice == "3":
                print("Thank you for using Encrypted File Vault.")
                break
            else:
                print("Invalid option. Please choose 1-3.")
        except (OSError, RuntimeError, ValueError) as error:
            print(f"Application error: {error}")


if __name__ == "__main__":
    main()
