import os  
import hashlib  
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
)

class Key(models.Model):
    user = models.OneToOneField('User', on_delete=models.CASCADE, related_name='encryption_key')
    encrypted_key = models.BinaryField()  
    iv = models.BinaryField()  
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'auth_key' 

    @staticmethod
    #Encrypts the user’s AES key using the master key
    def encrypt_key(aes_key, master_key): #enerates a random 16-byte (128-bit) Initialization Vector (IV)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(master_key, AES.MODE_CBC, iv)
        padded_key = pad(aes_key, AES.block_size)
        encrypted_key = cipher.encrypt(padded_key)
        return encrypted_key, iv

    @staticmethod
    #Decrypts the encrypted AES key using the IV and master key
    def decrypt_key(encrypted_key, iv, master_key):
        cipher = AES.new(master_key, AES.MODE_CBC, iv)
        padded_key = cipher.decrypt(encrypted_key)
        return unpad(padded_key, AES.block_size)

class User(AbstractBaseUser, PermissionsMixin):
    username = models.BinaryField(unique=True)  # Encrypted username
    email = models.BinaryField()  
    password_hash = models.CharField(max_length=256)  
    salt = models.CharField(max_length=32)  
    iv_username = models.BinaryField()  
    iv_email = models.BinaryField()  
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'auth_user'

    @staticmethod
    def encrypt_field(data, key):
        iv = get_random_bytes(AES.block_size)  
        cipher = AES.new(key, AES.MODE_CBC, iv) 
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data, iv

    @staticmethod
    def decrypt_field(encrypted_data, iv, key):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(encrypted_data)
        return unpad(padded_data, AES.block_size).decode('utf-8')

    @staticmethod
    def hash_password(password, salt=None):
        if salt is None:
            salt = os.urandom(16).hex()
        salted_password = password.encode('utf-8') + salt.encode('utf-8')
        password_hash = hashlib.sha256(salted_password).hexdigest()
        return password_hash, salt

    def verify_password(self, password):
        password_hash, _ = self.hash_password(password, self.salt)
        return password_hash == self.password_hash

class Note(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notes')
    content = models.BinaryField()
    iv_content = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'auth_note'

    @staticmethod
    def encrypt_note(content, key):
        return User.encrypt_field(content, key)

    @staticmethod
    def decrypt_note(encrypted_content, iv, key):
        return User.decrypt_field(encrypted_content, iv, key)
    

