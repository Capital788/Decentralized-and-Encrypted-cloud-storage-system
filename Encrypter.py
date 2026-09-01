from cryptography.fernet import Fernet
import os

class Crypto():

    def __init__(self):
        
        self.key = Fernet.generate_key()
        self.f = Fernet(self.key)

        
    def encryption_password(self, password):

        encrypted_password = self.f.encrypt(password.encode("utf-8"))

        with open("Password.key", "wb") as key_file:
            key_file.write(encrypted_password)

        return encrypted_password

        
    def decrypt_password(self, encrypted_password):

        real_password = self.f.decrypt(encrypted_password)

        return real_password
    

    def encrypt_bytes(self, chunk):

        """
        root, ext = os.path.splitext(file_path)
        encrypted_filepath = root + ".encrypted"
        
        try:

            with open(file_path, "rb") as file:
                original_data = file.read()

        
            encrypted_data = self.f.encrypt(original_data)

            with open(encrypted_filepath, "wb") as file:
                file.write(encrypted_data)
            
            print(f"\n----- File encrypted successfully: '{encrypted_filepath}' ✅ -----")

            return encrypted_filepath

        except FileNotFoundError:

            print(f"\n----- ❌ Error: The file '{file_path}' was not found. -----")
            return None
        
        except Exception as e:

            print(f"\n----- An error occurred during encryption: {e} -----")
            return None
        """

        return self.f.encrypt(chunk)
    

    def decrypt_bytes(self, chunk):

        return self.f.decrypt(chunk)


    

