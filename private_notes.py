# Authors: Christina Yi and Annie Pi

import pickle
import os
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class PrivNotes:
  MAX_NOTE_LEN = 2048;
  

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str): password for accessing the notes
      data (str) [Optional]: a hex-encoded serialized representation to load
                             (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional]: a hex-encoded checksum used to protect the data against
                                possible rollback attacks

    Raises:
      ValueError: malformed serialized format
    """
    
    if data is not None:
      # deserialize the data first to get the salt
      deser_data = pickle.loads(bytes.fromhex(data))
      [self.salt, self.nonces, self.kvs] = deser_data

    else:
      # if no data, initialize empty database and generate a new random salt
      self.kvs = {}
      self.nonces = {}
      self.salt = os.urandom(16)
        
    # now derive the source key
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.salt, 
                     iterations=2000000, backend=default_backend()
    )
    self.source_key = kdf.derive(bytes(password, 'ascii'))

    # if data is provided, now verify the checksum
    if data is not None:
      h = hmac.HMAC(self.source_key, hashes.SHA256())
      h.update(pickle.dumps([self.salt, self.nonces, self.kvs]))

      if checksum != h.finalize().hex():
          raise ValueError('Checksum is invalid, password is incorrect, or data has been tampered with.')

                                           
  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    # return hexified data and checksum
    # use HMAC not hash
    # expand data to involve everything self needs to store
    ser_data = [self.salt, self.nonces, self.kvs]
    deser_data = pickle.dumps(ser_data).hex()
    return deser_data, hmac.HMAC(self.source_key, hashes.SHA256()).hex()

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    # first, pad and hmac title
    padder = padding.PKCS7(16384).padder()
    unpadder = padding.PKCS7(16384).unpadder()
    hmacd_title = hmac.HMAC(padder.update(title) + padder.finalize(), hashes.SHA256())
    if hmacd_title in self.nonces:
      note = self.kvs[hmacd_title]
      aesgcm = AESGCM(self.source_key)
      decrypted_note = aesgcm.decrypt(self.nonces[hmacd_title], note, None)
      unpadded_note = unpadder.update(decrypted_note) + unpadder.finalize()
      # now change it to ASCII string
      note = unpadded_note.decode('ascii')
      return note
    return None


  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded') 
    padder = padding.PKCS7(16384).padder()
    # Pad and hash the title, pad the note
    hmacd_title = hmac.HMAC(padder.update(title) + padder.finalize(), hashes.SHA256())
    padded_note = padder.update(note) + padder.finalize()
    # encrypt the note and store the pair in kvs
    aesgcm = AESGCM(self.source_key)
    if hmacd_title in self.nonces:
      nonce = self.nonces[hmacd_title]
    else:
      nonce = os.urandom(16)
      self.nonces[hmacd_title] = nonce
    self.kvs[hmacd_title] = aesgcm.encrypt(nonce, padded_note, None)


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    padder = padding.PKCS7(16384).padder()
    hmacd_title = hmac.HMAC(padder.update(title) + padder.finalize(), hashes.SHA256())
    if hmacd_title in self.nonces:
      del self.kvs[hmacd_title]
      return True
    # return false if hmaced_title is not in nonces, because this means 
    # the title is not in kvs
    return False
