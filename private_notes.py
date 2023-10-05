import pickle
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

encrypted_kvs = {}

class PrivNotes:
  MAX_NOTE_LEN = 2048;
 

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    # first check if pw and checksum are correct
        
    #else...
    self.kvs = {} # initializing kvs to empty dictionary
    if data is not None:
      self.kvs = pickle.loads(bytes.fromhex(data)) # loading the notes from data

    else:
      """initialize empty database with pw as password""" 
      # use salt to derive key with PBKDF2_HMAC
      kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = os.urandom(16), 
                       iterations = 2000000) # add backend but idk what that really is
      key = kdf.derive(bytes(password, 'ascii'))
      
      nonce = os.urandom(12)
      # encrypt the notes
      for key in self.kvs:
        unencrypted_note = self.kvs[key]
        aesgcm = AESGCM(unencrypted_note)
        # ig this is where I'd add the padding?
        encrypted_note = aesgcm.encrypt(nonce, unencrypted_note, None)
        encrypted_kvs[key] = encrypted_note
        nonce += 1
      # ct = aesgcm.encrypt(nonce, data, aad)
      # aesgcm.decrypt(nonce, ct, aad)
      

                                           

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
    return pickle.dumps(self.kvs).hex(), hashes.SHA256(self.kvs).hex()

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    if title in self.kvs:
      return self.kvs[title]
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
    # have to account for if adversary queries more than one note. if so, we have to set a b so that 
    # the challenger (us) knows which one to actually encrypt/insert
    
    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')
    
    self.kvs[title] = note


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    if title in self.kvs:
      del self.kvs[title]
      return True

    return False
