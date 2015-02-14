"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
 
  // Strings to hash for generating keys.
  var mac_key_str = "ien230jofajo4#IEL3jkddifbvn39qpe";
  var enc_key_str = "5dncnzuOI$(#)NDKLEianeiei40slaek";
 
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  function setup_keys(master_password, salt) {
    priv.data.salt = salt;
    priv.secrets = {};
    priv.secrets.master_key = KDF(master_password, priv.data.salt);
    priv.secrets.mac_key = HMAC(priv.secrets.master_key, mac_key_str);
    priv.secrets.enc_key = HMAC(priv.secrets.master_key, enc_key_str);
    priv.secrets.enc_cipher = setup_cipher(
      bitarray_slice(priv.secrets.enc_key, 0, 128));
  }

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    priv.data = {};
    priv.data.version = "CS 255 Password Manager v1.0";
    priv.data.KVS = {};
    var salt = random_bitarray(128);
    setup_keys(password, salt);
    priv.data.update_num = 1;
    ready = true;
  };

  
  // We assume a 32 bit update_num.
  function update_num_to_bitarray(update_num) {
    var bytes = [];
    // Big endian.
    bytes[0] = (update_num >> 24) & 255;
    bytes[1] = (update_num >> 16) & 255;
    bytes[2] = (update_num >>  8) & 255;
    bytes[3] = (update_num      ) & 255;
    return hex_to_bitarray(byte_array_to_hex(bytes));
  }

  function header_mac() {
    return HMAC(priv.secrets.mac_key,
      bitarray_concat(update_num_to_bitarray(priv.data.update_num),
                      priv.secrets.master_key));
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  /** Note: We are using trusted_data_check as an update number rather than
    * a SHA-256 checksum.
    */
  keychain.load = function(password, repr, trusted_data_check) {
    var valid = true;
    ready = false;
    try {
      priv.data = JSON.parse(repr);
    } catch (err) {
      valid = false;
    }

    setup_keys(password, priv.data.salt);

    // If the update number is not available from the trusted store,
    // we will use the one in the database dump. We need this to generate
    // the next update number. 
    if (valid && trusted_data_check) {
      if (priv.data.update_num != trusted_data_check) {
        valid = false;
      }
    }

    // Check if master password is valid.
    // In case update number didn't come from trusted store, this
    // also authenticates the update number in the header.
    if (valid && !bitarray_equal(header_mac(),priv.data.header_mac)) {
      return false;
    }

    if (!valid) {
      throw "Integrity check failed. Invalid password database.";
    }
    ready = true;
    return true;
  };

  function mac_after_encrypt(update_num, hkey, ciphertext) {
    var input = bitarray_concat(hex_to_bitarray(hkey), ciphertext);
    input = bitarray_concat(update_num_to_bitarray(update_num), input);
    return HMAC(priv.secrets.mac_key, input);
  }

  // Check if the value in a KVS entry is properly authenticated.
  function is_valid_entry(hkey) {
    var entry = priv.data.KVS[hkey];
    var mac = mac_after_encrypt(priv.data.update_num, hkey, entry.ciphertext);
    return bitarray_equal(entry.mac, mac);
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    // This is an update. Re-auth all keys with incremented upate_num.
    // We assume password manager is single threaded. Otherwise, it
    // has to be locked during dump.
    for (var hkey in priv.data.KVS) {
      var entry = priv.data.KVS[hkey];
      if (!is_valid_entry(hkey)) {
        ready = false;
        throw "Record tampering detected";
      }
      entry.mac = mac_after_encrypt(priv.data.update_num+1,
                                    hkey, entry.ciphertext);
    }
    priv.data.update_num++;
    priv.data.header_mac = header_mac();
    var arr = [];
    var repr = JSON.stringify(priv.data);
    arr[0] = repr;
    arr[1] = priv.data.update_num;
    return arr;
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if (!ready) {
      throw "Password database not ready";
    }
    var hkey = bitarray_to_hex(HMAC(priv.secrets.mac_key, name));
    if (!(hkey in priv.data.KVS)) {
      return null;
    }
    var entry = priv.data.KVS[hkey];
    if (!is_valid_entry(hkey)) {
      ready = false;
      throw "Record tampering detected";
    }
    var padded_value = dec_gcm(priv.secrets.enc_cipher, entry.ciphertext);
    return string_from_padded_bitarray(padded_value, MAX_PW_LEN_BYTES);
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if (!ready) {
      throw "Password database not ready";
    }
    var entry = {};
    var hkey = bitarray_to_hex(HMAC(priv.secrets.mac_key, name));
    var padded_value = string_to_padded_bitarray(value, MAX_PW_LEN_BYTES);
    entry.ciphertext = enc_gcm(priv.secrets.enc_cipher, padded_value);
    entry.mac = mac_after_encrypt(priv.data.update_num,
                                  hkey, entry.ciphertext);
    priv.data.KVS[hkey] = entry;
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if (!ready) {
      throw "Password database not ready";
    }
    var hkey = bitarray_to_hex(HMAC(priv.secrets.mac_key, name));
    if (!(hkey in priv.data.KVS)) {
      return false;
    }
    return delete priv.data.KVS[hkey];
  }

  return keychain;
}

module.exports.keychain = keychain;
