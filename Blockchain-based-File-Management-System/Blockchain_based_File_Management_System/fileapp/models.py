import os
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.db import models
from django.contrib.auth import get_user_model
import base64
import hashlib
import json

User = get_user_model()


class FilePart(models.Model):
    """Model to store encrypted file parts"""
    file_upload = models.ForeignKey('FileUpload', on_delete=models.CASCADE, related_name='parts')
    part_number = models.IntegerField()
    part_hash = models.CharField(max_length=64)
    encrypted_part = models.BinaryField()
    encryption_key_id = models.CharField(max_length=64)  # Reference to key in KeyStorage

    class Meta:
        unique_together = ('file_upload', 'part_number')

    def __str__(self):
        return f"Part {self.part_number} of {self.file_upload}"


class KeyStorage(models.Model):
    """Model to store encryption keys securely"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    key_id = models.CharField(max_length=64, unique=True)
    encrypted_key = models.BinaryField()  # Encrypted with user's master key

    def __str__(self):
        return f"Key {self.key_id} for {self.user.username}"


class FileUploadManager:
    @staticmethod
    def split_and_encrypt_file(file_obj, user, num_parts=5):
        """
        Split file into parts and encrypt each part
        Returns: original file hash, list of part hashes, list of encryption keys
        """
        # Generate master key from user data (in production, use a more secure method)
        master_key = FileUploadManager.generate_master_key(user.username, user.password)

        # Read file content
        file_content = file_obj.read()
        file_obj.seek(0)  # Reset file pointer for potential future reads

        # Calculate file hash
        file_hash = hashlib.sha256(file_content).hexdigest()

        # Calculate part size
        file_size = len(file_content)
        part_size = math.ceil(file_size / num_parts)

        part_info = []

        # Split and encrypt each part
        for i in range(num_parts):
            start_pos = i * part_size
            end_pos = min(start_pos + part_size, file_size)
            part_data = file_content[start_pos:end_pos]

            # Generate unique encryption key for this part
            part_key = Fernet.generate_key()
            fernet = Fernet(part_key)

            # Encrypt the part
            encrypted_part = fernet.encrypt(part_data)

            # Calculate hash of the part
            part_hash = hashlib.sha256(part_data).hexdigest()

            # Encrypt the part key with master key
            key_id = hashlib.sha256(f"{file_hash}:{i}".encode()).hexdigest()
            encrypted_key = FileUploadManager.encrypt_with_master_key(part_key, master_key)

            part_info.append({
                'part_number': i,
                'part_hash': part_hash,
                'encrypted_part': encrypted_part,
                'key_id': key_id,
                'encrypted_key': encrypted_key
            })

        return file_hash, part_info

    @staticmethod
    def reassemble_file(file_upload, user):
        """Reassemble file from encrypted parts"""
        # Generate master key
        master_key = FileUploadManager.generate_master_key(user.username, user.password)

        # Get all parts ordered by part number
        parts = file_upload.parts.all().order_by('part_number')

        file_content = b''

        # Decrypt and combine parts
        for part in parts:
            # Get encryption key
            key_storage = KeyStorage.objects.get(key_id=part.encryption_key_id)
            part_key = FileUploadManager.decrypt_with_master_key(key_storage.encrypted_key, master_key)

            # Decrypt part
            fernet = Fernet(part_key)
            decrypted_part = fernet.decrypt(bytes(part.encrypted_part))

            # Add to reassembled file
            file_content += decrypted_part

        return file_content

    @staticmethod
    def generate_master_key(username, password):
        """Generate a master key based on user credentials"""
        # In production, use a more secure method with proper salting
        salt = b'static_salt_for_example'  # Use a secure random salt in production
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(f"{username}:{password}".encode()))
        return key

    @staticmethod
    def encrypt_with_master_key(data, master_key):
        """Encrypt data with master key"""
        fernet = Fernet(master_key)
        return fernet.encrypt(data)

    @staticmethod
    def decrypt_with_master_key(encrypted_data, master_key):
        """Decrypt data with master key"""
        fernet = Fernet(master_key)
        return fernet.decrypt(encrypted_data)


class Block(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    index = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)
    file_hash = models.CharField(max_length=64, unique=True)
    previous_hash = models.CharField(max_length=64)
    nonce = models.IntegerField()
    data = models.TextField()

    def hash_block(self):
        """Compute SHA-256 hash of the block."""
        block_data = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),
            "file_hash": self.file_hash,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "data": self.data,
            "user": self.user.username if self.user else "Unknown"
        }, sort_keys=True).encode()
        return hashlib.sha256(block_data).hexdigest()

    def __str__(self):
        return f"Block {self.index} - {self.file_hash[:10]}..."


class FileUpload(models.Model):
    """Model to store uploaded files securely."""
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Associate file with user
    file = models.FileField(upload_to='uploads/')
    file_hash = models.CharField(max_length=64, unique=True)

    def save(self, *args, **kwargs):
        """Compute file hash before saving (only if it's new)."""
        if not self.file_hash:
            self.file_hash = self.compute_file_hash()
        super().save(*args, **kwargs)

    def compute_file_hash(self):
        """Compute SHA-256 hash of the uploaded file."""
        hasher = hashlib.sha256()
        with self.file.open('rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def __str__(self):
        return f"File {self.file.name} - {self.file_hash[:10]}..."