'''
Created on 29/10/2014

@author: Jesper
'''
import hashlib, struct
import debug, highlevelcrypto, shared
from helper_sql import sqlQuery

def getMyAddresses():
    """
    Generator which returns all your addresses.
    """
    configSections = shared.config.sections()
    for addressInKeysFile in configSections:
        if addressInKeysFile != 'bitmessagesettings' and not shared.safeConfigGetBoolean(addressInKeysFile, 'chan'):
            isEnabled = shared.config.getboolean(
                addressInKeysFile, 'enabled')  # I realize that this is poor programming practice but I don't care. It's easier for others to read.
            if isEnabled:
                yield addressInKeysFile

def getPrivateSigningKey( address ):
    try:
        privSigningKeyBase58 = shared.config.get( address, 'privsigningkey' )
    except:
        return None
    
    return shared.decodeWalletImportFormat( privSigningKeyBase58 )

def getPublicSigningKey( address ):
    privSigningKey = getPrivateSigningKey( address )
    if privSigningKey is None:
        return None
    
    return highlevelcrypto.privToPub( privSigningKey.encode('hex') ).decode( 'hex' )

def has_pubkey_for(address, decodedAddress):
    # Can return True or False
    
    # If we need the public key for our own address or a chan,
    # we can compute it from the private key
    if shared.config.has_section( address ):
        return True
    
    # This is not an address where we know the private key.
    # See if we already have the public key in our database:
    _, toAddressVersion, toStreamNumber, toRipe = decodedAddress
    queryReturn = sqlQuery( "SELECT hash FROM pubkeys WHERE hash=? AND addressversion=?", toRipe, toAddressVersion)
    if queryReturn != []:
        return True
    
    if toAddressVersion >= 4: # If we are trying to send to address version >= 4 then the needed pubkey might be encrypted in the inventory.
        # If we have it we'll need to decrypt it and put it in the pubkeys table.
        _, toTag = compute_priv_encryption_key_and_tag(toAddressVersion, toStreamNumber, toRipe)
        queryreturn = sqlQuery(
            '''SELECT payload FROM inventory WHERE objecttype='pubkey' and tag=? ''', toTag)
        if queryreturn != []: # if there was a pubkey in our inventory with the correct tag, we need to try to decrypt it.
            for row in queryreturn:
                data, = row
                if shared.decryptAndCheckPubkeyPayload(data, address) == 'successful':
                    return True
                
        with shared.inventoryLock:
            for hash, storedValue in shared.inventory.items():
                objectType, streamNumber, payload, receivedTime, tag = storedValue
                if objectType == 'pubkey' and tag == toTag:
                    result = shared.decryptAndCheckPubkeyPayload(payload, address) #if valid, this function also puts it in the pubkeys table.
                    if result == 'successful':
                        return True
                    
     # We don't have the public key in our database.
    return False

def get_pubkey_for(address, decodedAddress=None):
    """
    Retrieve public key for an address.
    Provide the decodedAddress if you already have it. No need to decode it more than once.
    Returns None if pubkey not found, otherwise the following tuple:
    ( pubEncryptionKey, pubSigningKey, requiredAvgPOWNonceTrialsPerByte,
      requiredPayloadLengthExtraBytes, behaviourBitfield )
      
    The keys returned are in binary format.
    """
    # Can return None, "mobile-user-disallowed", or
    #    ( pubEncryptionKeyBase256, pubsigningKeyBase256,
    #      requiredAverageProofOfWorkNonceTrialsPerByte,
    #      requiredPayloadLengthExtraBytes,
    #      behaviourBitfield )
    
    if decodedAddress is None:
        decodedAddress = shared.decodeAddress( address )
        
    requiredAverageProofOfWorkNonceTrialsPerByte = shared.networkDefaultProofOfWorkNonceTrialsPerByte
    requiredPayloadLengthExtraBytes = shared.networkDefaultPayloadLengthExtraBytes
    
    # If we need the public key for our own address or a chan,
    # we can compute it from the private key
    if shared.config.has_section( address ):
        try:
            privSigningKeyBase58 = shared.config.get(
                address, 'privsigningkey')
            privEncryptionKeyBase58 = shared.config.get(
                address, 'privencryptionkey')
        except:
            debug.logger.error( tr.translateText("MainWindow", "Error! Could not find sender address (your address) in the keys.dat file." ) )
            return None

        privSigningKeyHex = shared.decodeWalletImportFormat(
            privSigningKeyBase58).encode('hex')
        privEncryptionKeyHex = shared.decodeWalletImportFormat(
            privEncryptionKeyBase58).encode('hex')

        pubSigningKey = highlevelcrypto.privToPub(
            privSigningKeyHex).decode('hex')[1:]
        pubEncryptionKey = highlevelcrypto.privToPub(
            privEncryptionKeyHex).decode('hex')[1:]
            
        return ( pubEncryptionKey, pubSigningKey, 
                 requiredAverageProofOfWorkNonceTrialsPerByte,
                 requiredPayloadLengthExtraBytes,
                 "\x00\x00\x00\x01" )
    
    # This is not an address where we know the private key.
    # See if we already have the public key in our database:
    _, addressVersion, streamNumber, ripe = decodedAddress
    queryReturn = sqlQuery( "SELECT transmitdata FROM pubkeys WHERE hash=? AND addressversion=?", ripe, addressVersion)
    if queryReturn != []:
        pubkeyPayload = queryReturn[0][0]
        return decode_pubkey_payload( pubkeyPayload, addressVersion )

        # The pubkey message is stored the way we originally received it
        # which means that we need to read beyond things like the nonce and
        # time to get to the actual public keys.
    
                    
    # We don't have the public key in our database.
    return None

def decode_pubkey_payload(pubkeyPayload, addressVersion):
    """
    Returns a tuple ( pubEncryptionKey, pubsigningKey,
                      requiredAverageProofOfWorkNonceTrialsPerByte,
                      requiredPayloadLengthExtraBytes,
                      behaviorBitfield )
    by decoding the payload of a pubkey message.
    Can also return "mobile-user-disallowed"
    
    The keys are in binary format (base 256)
    """
    requiredAverageProofOfWorkNonceTrialsPerByte = shared.networkDefaultProofOfWorkNonceTrialsPerByte
    requiredPayloadLengthExtraBytes = shared.networkDefaultPayloadLengthExtraBytes
    if addressVersion <= 3:
        readPosition = 8  # to bypass the nonce
    elif addressVersion >= 4:
        readPosition = 0 # the nonce is not included here so we don't need to skip over it.
    pubkeyEmbeddedTime, = struct.unpack(
        '>I', pubkeyPayload[readPosition:readPosition + 4])
    # This section is used for the transition from 32 bit time to 64
    # bit time in the protocol.
    if pubkeyEmbeddedTime == 0:
        pubkeyEmbeddedTime, = struct.unpack(
            '>Q', pubkeyPayload[readPosition:readPosition + 8])
        readPosition += 8
    else:
        readPosition += 4
    readPosition += 1  # to bypass the address version whose length is definitely 1
    _, streamNumberLength = shared.decodeVarint(
        pubkeyPayload[readPosition:readPosition + 10])
    readPosition += streamNumberLength
    behaviorBitfield = pubkeyPayload[readPosition:readPosition + 4]
    # Mobile users may ask us to include their address's RIPE hash on a message
    # unencrypted. Before we actually do it the sending human must check a box
    # in the settings menu to allow it.
    if shared.isBitSetWithinBitfield(behaviorBitfield,30): # if receiver is a mobile device who expects that their address RIPE is included unencrypted on the front of the message..
        if not shared.safeConfigGetBoolean('bitmessagesettings','willinglysendtomobile'): # if we are Not willing to include the receiver's RIPE hash on the message..
#                logger.info('The receiver is a mobile user but the sender (you) has not selected that you are willing to send to mobiles. Aborting send.')
#                shared.UISignalQueue.put(('updateSentItemStatusByAckdata',(ackdata,tr.translateText("MainWindow",'Problem: Destination is a mobile device who requests that the destination be included in the message but this is disallowed in your settings.  %1').arg(unicode(strftime(shared.config.get('bitmessagesettings', 'timeformat'),localtime(int(time.time()))),'utf-8')))))
            # if the human changes their setting and then sends another message or restarts their client, this one will send at that time.
            return "mobile-user-disallowed"
    readPosition += 4  # to bypass the bitfield of behaviors
    pubSigningKeyBase256 = pubkeyPayload[readPosition:readPosition+64]
    readPosition += 64
    pubEncryptionKeyBase256 = pubkeyPayload[readPosition:readPosition+64]
    readPosition += 64
    
    requiredAverageProofOfWorkNonceTrialsPerByte
    
    # Let us fetch the amount of work required by the recipient.
    if addressVersion >= 3:
        requiredAverageProofOfWorkNonceTrialsPerByte, varintLength = shared.decodeVarint(
            pubkeyPayload[readPosition:readPosition + 10])
        readPosition += varintLength
        requiredPayloadLengthExtraBytes, varintLength = shared.decodeVarint(
            pubkeyPayload[readPosition:readPosition + 10])
        readPosition += varintLength
        if requiredAverageProofOfWorkNonceTrialsPerByte < shared.networkDefaultProofOfWorkNonceTrialsPerByte:  # We still have to meet a minimum POW difficulty regardless of what they say is allowed in order to get our message to propagate through the network.
            requiredAverageProofOfWorkNonceTrialsPerByte = shared.networkDefaultProofOfWorkNonceTrialsPerByte
        if requiredPayloadLengthExtraBytes < shared.networkDefaultPayloadLengthExtraBytes:
            requiredPayloadLengthExtraBytes = shared.networkDefaultPayloadLengthExtraBytes
    return ( pubEncryptionKeyBase256, pubSigningKeyBase256,
             requiredAverageProofOfWorkNonceTrialsPerByte,
             requiredPayloadLengthExtraBytes,
             behaviorBitfield )


def compute_priv_encryption_key_and_tag( addressVersionNumber, streamNumber, ripe ):
    doubleHashOfAddressData = hashlib.sha512(hashlib.sha512(shared.encodeVarint(
            addressVersionNumber) + shared.encodeVarint(streamNumber) + ripe).digest()).digest()
    privEncryptionKey = doubleHashOfAddressData[:32] # Note that this is the first half of the sha512 hash.
    tag = doubleHashOfAddressData[32:] # Note that this is the second half of the sha512 hash.
    return privEncryptionKey, tag
        
