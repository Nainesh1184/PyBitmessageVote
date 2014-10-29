'''
Created on 18/09/2014

@author: Jesper
'''
import hashlib, json, threading, time

from addresses import decodeAddress, encodeVarint, decodeVarint
from debug import logger
from pyelliptic import arithmetic
import shared

from consensus import ConsensusProtocol
from consensus_data import ConsensusData
from ringsignature import RingSignature
import helper_keys
from ec import Curve, ECHelper, Point

# Set to True to log debug info
DEBUG = True

class VotingData(ConsensusData):
    '''
    classdocs
    '''

    CURVE = Curve( 'secp256k1' )
    
    # Set to True to disable checking that the public keys provided
    # actually match the addresses.
    DISABLE_CHECKING_PUBLIC_KEYS_MATCH_ADDRESSES = False
    
    COMPUTING_VOTE = "computing"

    def __init__(self, blockchain, time_data, question, answers, addresses, public_keys=None, dont_check=False ):
        """
        Constructor
        
        blockchain and time_data are passed on to the ConsensusData constructor.
        question is a string that defines the election question.
        answers is a list of strings that define the possible answers for the election.
        addresses is a list of Bitmessage addresses that define the registered voters.
        public_keys is a list of public keys corresponding to the Bitmessage addresses.
            If public_keys is None or at least one of the public_keys is None,
            we check if we have the missing public keys locally or request them
            if necessary.
            Each entry in the pubkey list is a tuple ( signingKey, encryptionKey )
                (if not None)
        dont_check, if set to True, bypasses basic validation on question, answers and addresses
        """
        self.blockchain = blockchain
        self.time_data = time_data
        self.question = question
        self.answers = answers
        self.addresses = addresses
        self.public_keys = public_keys
        self.dont_check = dont_check
        
        # A list of predetermined votes to send once the election starts.
        # This list is used by the daemon API to send votes when the election
        # starts.
        # Each entry should be a ( address, vote, vote_delay )-tuple.
        self.predetermined_votes = []
        
    def initialize( self ):
        """
        Initialization function, override this in extending classes.
        Run all initialization here instead of in the constructor
        """
        # If no public keys provided or at least one unknown public key,
        # try to load the public keys from the addresses to see if we
        # now have all required public keys
        if self.public_keys is None or (None,None) in self.public_keys:
            self.load_public_keys()
        self.extract_signing_keys()
        
        if not self.dont_check:
            self.check_voting_values()
        
        ConsensusData.__init__(self, ConsensusData.DATA_TYPE_VOTING, self.blockchain, self.time_data )
        
            
    def has_all_public_keys(self):
        """
        Check if we have public keys for all addresses
        """
        return len( self.addresses ) == len( self.public_keys ) and \
            filter( lambda pk: pk is None or pk == ( None, None ), self.public_keys ) == []
            
    def load_public_keys(self):
        """
        Loads all public keys from the list of addresses.
        Requests those that we don't have.
    
        NOTE: This is inefficient in the sense that it reloads all
              keys every time it is run (and it is run whenever we
              receive a public key that we need for this election).
              It would be better to simply reload the missing keys.
        """
        self.public_keys = []
        for address in self.addresses:
            decodedAddress = decodeAddress( address )
            if helper_keys.has_pubkey_for( address, decodedAddress ):
                pubkey_tuple = helper_keys.get_pubkey_for( address, decodedAddress )
                pubEncryptionKeyBase256, pubSigningKeyBase256, _, _, _ = pubkey_tuple
                self.public_keys.append( ( pubSigningKeyBase256, pubEncryptionKeyBase256 ) )
            else:
                self.public_keys.append( ( None, None ) )
                log_warn( "Missing pubkey for %s" % address )
                self.missing_public_key( address )
#                if not helper_keys.is_awaiting_pubkey_for( addressVersion, streamNumber, ripe=ripe ):
#                    shared.workerQueue.put( ( "requestPubkey", ( address, decodedAddress ) ) )

    def missing_public_key(self, address ):
        PUBKEY_REQUEST_WAIT_SECONDS = 60 * 60 * 24
        last_request_time = self.settings_get_pubkey_last_request_time( address )
        if last_request_time is not None and last_request_time > time.time() - PUBKEY_REQUEST_WAIT_SECONDS:
            # We requested this pubkey recently, so let's not do it again right now
            
            # However, we need to put the tag in neededPubkeys in case the user just restarted the client
            _, addressVersionNumber, streamNumber, ripe = decodeAddress(address)
            if addressVersionNumber <= 3:
                shared.neededPubkeys[ripe] = 0
            elif addressVersionNumber >= 4:
                tag = hashlib.sha512(hashlib.sha512(encodeVarint(addressVersionNumber)+encodeVarint(streamNumber)+ripe).digest()).digest()[32:] # Note that this is the second half of the sha512 hash.
                if tag not in shared.neededPubkeys:
                    privEncryptionKey = hashlib.sha512(hashlib.sha512(encodeVarint(addressVersionNumber)+encodeVarint(streamNumber)+ripe).digest()).digest()[:32] # Note that this is the first half of the sha512 hash.
                    import highlevelcrypto
                    shared.neededPubkeys[tag] = (address, highlevelcrypto.makeCryptor(privEncryptionKey.encode('hex'))) # We'll need this for when we receive a pubkey reply: it will be encrypted and we'll need to decrypt it.

            return 
        
        self.settings_set_pubkey_last_request_time( address, time.time() )
        shared.workerQueue.put( ( "requestPubkey", address ) )

    def get_amount_public_keys(self):
        return len( filter( lambda ks: ks != (None, None), self.public_keys ) )
                    
    def validate_public_keys_with_addresses(self):
        """
        Checks that all the public keys match the addresses.
        
        Raises an exception if there is a mismatch.
        
        Assumes that len( self.addresses ) == len( self.public_keys )
        """
        valid_addresses = 0
        for address, pk in zip( self.addresses, self.public_keys ):
            if pk is None or pk == (None, None):
                continue
            signingKey, encryptionKey = pk
            _, _, _, address_ripe = decodeAddress( address )
            ripe_hash = hashlib.new('ripemd160')
            sha_hash = hashlib.new('sha512')
            sha_hash.update( '\x04' + signingKey + '\x04' + encryptionKey )
            ripe_hash.update( sha_hash.digest() )
            if ripe_hash.digest() != address_ripe:
                raise Exception( 'Public keys ripe mismatch: %s != %s' % ( repr( address_ripe ), repr( ripe_hash.digest() ) ) )
            valid_addresses += 1
            
        log_debug( "Validated %d/%d addresses from the public keys" % ( valid_addresses, len( self.addresses ) ) )
                    
    def extract_signing_keys(self):
        """
        Creates the list self.signing_keys from all the entries in self.public_keys.
        If entry is a tuple ( signingKey, encryptionKey ), append the signing key.
        Otherwise, append None
        """
        self.signing_keys = map( lambda pks: pks[0] if pks is not None else None, self.public_keys )
        log_debug( "Extracting signing keys: %s" % map( lambda pks: len(pks) if pks is not None else 0, self.public_keys ) )
                    
    def check_voting_values( self ):
        """
        Check that all provided values are valid
        """
        if len( self.question ) == 0:
            raise Exception( 'No question provided' )
        
        if len( self.answers ) <= 1:
            raise Exception( 'At least two answers must be provided' )
        
        if len( self.addresses ) <= 2:
            raise Exception( 'At least three addresses must be provided' )
        
        invalidAddresses = [a for a in self.addresses if decodeAddress(a)[0] != 'success']
        if len( invalidAddresses ) > 0:
            raise Exception( 'Invalid addresses: %s' % invalidAddresses )
        
        if not VotingData.DISABLE_CHECKING_PUBLIC_KEYS_MATCH_ADDRESSES:
            self.validate_public_keys_with_addresses()
    
    def cast_vote(self, fromaddress, answerNo, previous_vote_hash):
        """
        Cast a vote asynchronously and mark the fromaddress as having voted.
        """
        shared.workerQueue.put( ("castVote", ( self.cp.id, fromaddress, answerNo, previous_vote_hash ) ) )    
        self.settings_set_already_voted_address( fromaddress, VotingData.COMPUTING_VOTE )
        
    @staticmethod
    def compute_and_cast_vote(consensus_id, fromaddress, answerNo, previous_vote_hash):
        """
        Generates the answer message with linkable ring signature and posts
        it using ConsensusProtocol.post_message(message).
        
        This method should be invoked by
        shared.workerQueue.put( ("castVote", ( consensus_id, fromaddress, answerNo, previous_vote_hash ) ) ) 
        """
        log_debug("compute_and_cast_vote(%d, %s, %d)" % ( consensus_id, fromaddress, answerNo ) )
        cp = ConsensusProtocol.read_from_id( consensus_id )
        if cp is None:
            return None
        cp.update_status_bar( "Computing vote..." )
        
        # We can allow votes to be cast up until the commitment phase started.
        # It can happen that a user queues the vote in the work queue just before
        # the deadline, and the posting window closes in the meantime.
        # We still want the vote to be sent.
        if cp.get_status() > ConsensusProtocol.STATUS_COMMITMENT_PHASE:
            return None
        
        if answerNo < 0 or answerNo >= len( cp.data.answers ):
            raise Exception( 'Invalid answer number: %d' % answerNo )
        
        if fromaddress not in cp.data.addresses:
            raise Exception( 'Vote casting address not in list of voter addresses! (%s)' % fromaddress )

        privSigningKey = helper_keys.getPrivateSigningKey( fromaddress )
        if privSigningKey is None:
            raise Exception( "Vote: We don't have the private keys for address %s" % fromaddress )
        privSigningKey = arithmetic.decode( privSigningKey, 256 )
        
        signer_index = cp.data.addresses.index( fromaddress )
        
        message = VotingData.encode_vote( answerNo, previous_vote_hash )

        rs = RingSignature.sign_message(message, cp.data.signing_keys, privSigningKey, signer_index)
        c0, ss, Y_tilde = rs
        
        data = VotingData.encode_ring_signature( message, c0, ss, Y_tilde)
        message_hash = cp.post_message( data )
        cp.update_status_bar( '' )
        cp.data.settings_set_already_voted_address( fromaddress, message_hash )
        cp.refresh_ui()
        
    def message_valid( self, data ):
        """
        Check if a message is valid. This is done by verifying the
        ring signature in the message
        
        Called by the protocol to validate messages
        """
        log_debug("message_valid()")
        message, c_0, ss, Y_tilde = self.decode_ring_signature( data )
        VotingData.decode_vote( message )
        if RingSignature.verify_message(message, self.signing_keys, c_0, ss, Y_tilde):
            return True
        else:
            return False
    
    def compute_results( self, accepted_message_tuples ):
        """
        Compute the results and return them as a string.
        
        Called by the protocol to create results messages
        """
        log_debug("compute_results(%d tuples)" % ( len( accepted_message_tuples ) ) )
        return json.dumps( self.get_answers_and_votes( accepted_message_tuples ) )
    
    def compute_hash( self ):
        """
        Compute the hash of the election data.
        
        Called by the protocol to compute the hash and
        in turn the chan address for the election.
        """
        log_debug("compute_hash()" )
        if self.question is None or \
           self.answers in (None, []) or \
           self.addresses in (None, []) or \
           self.time_data is None:
            raise Exception( 'Could not compute hash. Missing question, answers, addresses, and/or time_data' )
        
        sha = hashlib.new( 'sha256' )
        hashedString = self.question + ";" + ",".join( self.answers ) + ";" + ",".join( self.addresses ) + ";" + \
                        str( self.blockchain ) + ";" + str( self.time_data )
        sha.update( hashedString )
        return sha.hexdigest()
    
    def status_changed(self, new_status):
        """
        The election status has changed.
        
        Called by the protocol when status changes.
        """
        
        # If the election opens, let's send any votes that we have stored 
        if new_status == ConsensusProtocol.STATUS_POSTING:
            self.schedule_predetermined_votes()
    
    def schedule_predetermined_votes(self):
        """
        Schedule predetermined votes to be computed and cast
        according to the delay.
        
        Recall the predetermined_votes is a list of ( address, vote, vote_delay )-tuples
        """
        if self.cp.get_status() != ConsensusProtocol.STATUS_POSTING:
            return
        
        pv = self.predetermined_votes
        self.predetermined_votes = []
        for vote in pv:
            _, _, delay = vote
            threading.Timer( delay, self.send_predetermined_vote, (vote, ) ).start()
            
    def send_predetermined_vote(self, vote):
        """
        Callback for the above timer to actually cast the votes.
        """
        address, answer_no, _ = vote
        self.cast_vote( address, answer_no )
        
    def get_my_voter_addresses(self):
        """
        Returns a tuple ( address, previous_vote_hash ) of all controlled addresses
        which are registered for voting. previous_vote_hash is None if the address
        hasn't cast a vote previously
        """
        return [ ( addr, self.settings_get_already_voted_address( addr ) ) for addr in self.addresses if shared.config.has_section( addr ) ]
    
    def get_answers_dict(self):
        """
        Returns a list of ( answer_no, answer )-tuples for all the answers
        """
        return dict( [( i, self.answers[i] ) for i in range( len( self.answers ) )]  )

    def get_answers_and_votes(self, message_tuples=None ):
        """
        Returns a list of ( answer_no, answer, amount_votes=0 ) for each answer_no
        Doesn't count votes from addresses which have sent more than one vote
        """
        votes = map( lambda v: v[2], filter( lambda v: v[5], self.get_individual_votes_with_validity( message_tuples ) ) )
        
        # Prepare a dictionary where the answer numbers are keys and the
        # values are the amount of votes for that answer number
        votes_dict = {}
        for vote in votes:
            if not vote in votes_dict:
                votes_dict[vote] = 0
            votes_dict[vote] += 1
            
        
        return [( i, self.answers[i], votes_dict[i] if i in votes_dict else 0) for i in range( len( self.answers ) )] 
    
    def get_individual_votes_with_validity(self, message_tuples=None):
        """
        Returns a list of tuples (time, tag, answer, hash, previous_vote_hash, valid)
        The last element 'valid' informs of whether or not this vote could be counted
        in the final tally
        
        We do this by creating a tree of votes for each tag.
        The root vote for each tag is the "original vote" (the one without a previous hash)
            (If more than one root vote exists for a tag, discard all votes with that tag)
        The tree forms a chain where revotes link with the votes they are supposed to overwrite.
        
        For each tag, go through the tree from the root vote, and ensure that each vote has at most 1
        vote below them.
            If 1 "subvote", proceed to that subvote
            If 0, current vote is the valid one
        """
        import time
        start_time = time.time()
        votes = self.get_individual_votes(message_tuples)
        
        valid_votes = {}
        
        tags = {}
        for v in votes:
            tag = v[1]
            if tag not in tags:
                tags[tag] = []
            tags[tag].append( v )
            
        # Now we have a map of all votes by their tag
        # So we'll go through each tag 
        for tag, votes_with_tag in tags.iteritems():

            votes_by_hash = dict( ( ( v[3], ( v, [] )  ) for v in votes_with_tag ) )
                
            # For this tag, we now have a map of all votes by their hash
            # We'll now go through all revotes and assign them as children
            # of the correct original vote
            for v in filter( lambda v: v[4] is not None, votes_with_tag ):
                vote_hash, previous_hash = v[3], v[4]
                if previous_hash not in votes_by_hash:
                    continue
                
                log_debug( "Setting %s as child of %s with tag %s" % ( vote_hash.encode('hex')[:8], previous_hash.encode('hex')[:8], tag.encode_binary().encode('hex')[:8] ) )
                votes_by_hash[ previous_hash ][1].append( vote_hash )
                
            log_debug( "Votes by hash: %s" % votes_by_hash )
            log_debug( "Votes by hash values:" )
            for v in votes_by_hash.values():
                log_debug( "Vote: %d %s" % ( len( v ), v[0], ) )
                log_debug( "Child hashes: %s" % ( map( lambda h: h.encode('hex')[:8], v[1] ), ) )
                
            # Now we go through all original votes and ensure that
            # their revotes form a single "line" from the original vote
            # to the revote (If e.g. one vote in the chain has more than
            # 1 child, we'll discard everything)
            
            def _get_end_vote( vote_hash ):
                if vote_hash not in votes_by_hash:
                    # Unknown vote
                    return None
                vote, child_hashes = votes_by_hash[ vote_hash ]
                if len( child_hashes ) == 0:
                    # End of the chain
                    return vote
                elif len( child_hashes ) == 1:
                    return _get_end_vote( child_hashes[0] )
                else:
                    # More than one child... discard
                    return None
                
            # v[0][4]: 0 is v in ( v, <list> ), 4 is previous_vote_hash
            # So this is all original votes (i.e. non-revotes)
            original_votes = filter( lambda v: v[0][4] is None, votes_by_hash.values() )
            if len( original_votes ) != 1:
                # Discard all votes with this tag if it has more
                # than one original vote
                continue
            
            original_vote = original_votes[0]
            valid_vote = _get_end_vote( original_vote[0][3] )
            if valid_vote is not None:
                vote_hash = valid_vote[3]
                valid_votes[vote_hash] = valid_vote
            
        log_debug( "checking votes with validity took %.3f seconds" % ( time.time()-start_time, ) )
        for v in valid_votes.values():
            time, tag, answer, vote_hash, previous_vote_hash = v
            yield ( time, tag, answer, vote_hash, previous_vote_hash, True )
        for v in filter( lambda v: v[3] not in valid_votes, votes ):
            time, tag, answer, vote_hash, previous_vote_hash = v
            yield ( time, tag, answer, vote_hash, previous_vote_hash, False )
        
    
    def get_individual_votes(self, message_tuples=None):
        """
        Returns a list of tuples (time, tag, answer, hash, previous_vote_hash)
        The last element 'votes_with_tag' informs of how many votes has been
        received from this tag,and should thus be 1 for the vote to not
        be discarded
        """
        if message_tuples is None:
            message_tuples = self.cp.get_all_messages()
            
        times = map( lambda m: m[0], message_tuples )
        hashes = map( lambda m: m[2], message_tuples )
        # messages_decoded is a list of ( message, c_0, ss, tag )
        # tag is an EC point
        messages_decoded = map( lambda m: self.decode_ring_signature( m[1] ), message_tuples )
        
        votes = map( lambda m: VotingData.decode_vote( m[0] ), messages_decoded )
        answers = map( lambda v: v[0], votes )
        previous_vote_hashes = map( lambda v: v[1], votes )
        tags = map( lambda m: m[3], messages_decoded )
        
        return zip( times, tags, answers, hashes, previous_vote_hashes )
    
    def get_discarded_vote_count(self):
        """
        Returns the amount of votes discarded because the voter
        cast more than one vote.
        """
        individual_votes = self.get_individual_votes()
        discarded_votes = filter( lambda v: v[4] != 1, individual_votes )
        return len( discarded_votes )
    
    def clear_settings(self):
        self.settings_set_already_voted_addresses({})
        self.settings_clear_pubkey_last_request_times()
        
    def settings_get_already_voted_addresses(self):
        if not "voted_addresses" in self.cp.settings:
            return {}
        hex_encoded = self.cp.settings["voted_addresses"]
        return dict( ( ( addr, pvh.decode('hex') ) for addr, pvh in hex_encoded.items() ) )
    def settings_get_already_voted_address(self, address):
        voted_addresses = self.settings_get_already_voted_addresses()
        if address in voted_addresses:
            return voted_addresses[address]
        else:
            return None
    def settings_set_already_voted_addresses(self, addresses):
        hex_encoded = dict( ( ( addr, pvh.encode('hex') ) for addr, pvh in addresses.items() ) )
        self.cp.settings["voted_addresses"] = hex_encoded
        self.cp.store()
    def settings_set_already_voted_address(self, address, vote_hash):
        addresses = self.settings_get_already_voted_addresses()
        addresses[address] = vote_hash
        self.settings_set_already_voted_addresses( addresses )
            
    def settings_get_pubkey_last_request_time(self, address):
        if not "pubkeys_last_request_time" in self.cp.settings:
            self.cp.settings["pubkeys_last_request_time"] = {} 
        return self.cp.settings["pubkeys_last_request_time"][address] \
                    if address in self.cp.settings["pubkeys_last_request_time"] \
                    else None
    def settings_set_pubkey_last_request_time(self, address, time):
        if not "pubkeys_last_request_time" in self.cp.settings:
            self.cp.settings["pubkeys_last_request_time"] = {}
        if time is None:
            if address in self.cp.settings["pubkeys_last_request_time"]:
                del self.cp.settings["pubkeys_last_request_time"][address]
        else:
            self.cp.settings["pubkeys_last_request_time"][address] = time
        self.cp.store()
    def settings_clear_pubkey_last_request_times(self):
        if "pubkeys_last_request_time" in self.cp.settings:
            del self.cp.settings["pubkeys_last_request_time"]
            
    def settings_get_first_load(self):
        return self.cp.settings["first_load"] if "first_load" in self.cp.settings else True
    def settings_set_first_load(self, first_load):
        self.cp.settings["first_load"] = first_load
        self.cp.store()
        

    def to_json(self):
        result = ConsensusData.to_json(self)
        result.update( { "question": self.question, "answers": self.answers, 
                         "addresses": self.addresses, "pubkeys": map( lambda pk: ( pk[0].encode('hex'), pk[1].encode('hex') ), self.public_keys ) } )
        return result

    def pack_binary( self ):
        """
        Pack the data into a binary string for storage in DB.
        The standard format is [ dataType(varInt) ][ actual data ]
        
        The actual data is stored as follows:
        [ length of question (varInt) ][ question ]
        [ amount of answers (varInt) ]
        for each answer:
            [ length of answer (varInt) ][ answer }
        [ amount of addresses (varInt) ]
        for each address:
            [ length of address (varInt) ][ address }
        [ amount of public keys (varInt) ]
        for each pubkey:
            [ length of signing pubkey (varInt) ][ signing pubkey }
            [ length of encryption pubkey (varInt) ][ encryption pubkey ]
        """
        result = ConsensusData.pack_binary_header(ConsensusData.DATA_TYPE_VOTING, self.blockchain, self.time_data)
        
        result += encodeVarint( len( self.question ) )
        result += self.question
        
        result += encodeVarint( len( self.answers ) )
        for answer in self.answers:
            result += encodeVarint( len( answer ) )
            result += answer
            
        result += encodeVarint( len( self.addresses ) )
        for address in self.addresses:
            result += encodeVarint( len( address ) )
            result += address
            
        if self.public_keys is None:
            result += encodeVarint( 0 )
        else:
            result += encodeVarint( len( self.public_keys ) )
            for pubkey in self.public_keys:
                if pubkey is None:
                    result += encodeVarint( 0 )
                    result += encodeVarint( 0 )
                else:
                    # Signing key first
                    if pubkey[0] is None:
                        result += encodeVarint( 0 )
                    else:
                        result += encodeVarint( len( pubkey[0] ) )
                        result += pubkey[0]
                        
                    # Then encryption key
                    if pubkey[1] is None:
                        result += encodeVarint( 0 )
                    else:
                        result += encodeVarint( len( pubkey[1] ) )
                        result += pubkey[1]
            
        return result
    
    @staticmethod
    def unpack_binary( data, blockchain, time_data, dont_check ):
        """
        Unpacks the following values from a binary string: question, answers, addresses, public_keys
        
        Variables blockchain, time_data, and dont_check must be provided for the constructor.
        """

        read_pos = 0

        question_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        question = data[read_pos:read_pos+question_len]
        read_pos += question_len
        
        answer_count, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        answers = []
        for _ in range( answer_count ):
            answer_len, offset = decodeVarint( data[read_pos:read_pos+10] )
            read_pos += offset
            answer = data[read_pos:read_pos+answer_len]
            read_pos += answer_len
            answers.append( answer )

        address_count, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        addresses = []
        for _ in range( address_count ):
            address_len, offset = decodeVarint( data[read_pos:read_pos+10] )
            read_pos += offset
            address = data[read_pos:read_pos+address_len]
            read_pos += address_len
            addresses.append( address )

        public_key_count, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        public_keys = []
        for _ in range( public_key_count ):
            signing_pubkey_len, offset = decodeVarint( data[read_pos:read_pos+10] )
            read_pos += offset
            if signing_pubkey_len == 0:
                signing_pubkey = None
            else:
                signing_pubkey = data[read_pos:read_pos+signing_pubkey_len]
                read_pos += signing_pubkey_len

            encryption_pubkey_len, offset = decodeVarint( data[read_pos:read_pos+10] )
            read_pos += offset
            if encryption_pubkey_len == 0:
                encryption_pubkey = None
            else:
                encryption_pubkey = data[read_pos:read_pos+encryption_pubkey_len]
                read_pos += encryption_pubkey_len
                
            pubkey = ( signing_pubkey, encryption_pubkey )
            public_keys.append( pubkey )
            
        return VotingData( blockchain, time_data, question, answers, addresses, public_keys, dont_check )
    
    @staticmethod
    def encode_vote( answer_no, previous_vote_hash ):
        """
        Encode a vote.
        
        Format:
        [ answer_no(varInt) ]
        [ pvh_len(varInt) ][ pvh ]
        """
        if previous_vote_hash is None:
            previous_vote_hash = ""
        
        data = encodeVarint( answer_no )
        
        data += encodeVarint( len( previous_vote_hash ) )
        data += previous_vote_hash
        
        return data
        
    @staticmethod
    def decode_vote( data ):
        """
        Decode a vote,
        
        returns ( answer_no, previous_vote_hash )
        """
        read_pos = 0

        answer_no, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        previous_vote_hash_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        previous_vote_hash = data[read_pos:read_pos+previous_vote_hash_len]
        read_pos += previous_vote_hash_len
        
        if previous_vote_hash == "":
            previous_vote_hash = None
        
        return answer_no, previous_vote_hash
        
        
    @staticmethod
    def encode_ring_signature( message, c0, ss, Y_tilde ):
        """
        Encode a ring signature for a vote.
        
        Note that we don't need to encode the public
        keys into the addresses, because everybody knows
        them from the election data.
        
        The format is as follows:
        
        [ MAGIC_ID ]
        [ c_0_length(varInt) ][ c_0 ]
        [ ss_length(varInt) ]
        for each s_i in ss:
            [ s_i_length(varInt) ][ s_i ]
        [ Y_tilde_x_length(varInt) ][ Y_tilde_x ]
        [ Y_tilde_y_length(varInt) ][ Y_tilde_y ]
        """
        data = RingSignature.MAGIC_ID
        c0_bin = ECHelper.int2bin( c0 )
        data += encodeVarint( len( c0_bin ) )
        data += c0_bin
        
        data += encodeVarint( len( ss ) )
        for s in ss:
            s_bin = ECHelper.int2bin( s )
            data += encodeVarint( len( s_bin ) )
            data += s_bin
            
        Y_tilde_x_bin = ECHelper.int2bin( Y_tilde.x )
        data += encodeVarint( len( Y_tilde_x_bin ) )
        data += Y_tilde_x_bin
        Y_tilde_y_bin = ECHelper.int2bin( Y_tilde.y )
        data += encodeVarint( len( Y_tilde_y_bin ) )
        data += Y_tilde_y_bin
            
        data += encodeVarint( len( message ) )
        data += message
        
        return data
    
    @staticmethod
    def decode_ring_signature( data ):
        """
        Decode a ring signature and returns ( message, c_0, ss, Y_tilde )
        """
        if not data[:len( RingSignature.MAGIC_ID )] == RingSignature.MAGIC_ID:
            raise Exception( "Start of election message isn't RingSig Magic ID: %s" % repr( data[:len(RingSignature.MAGIC_ID)] ) )

        readPosition = len( RingSignature.MAGIC_ID )
        
        c0_len, offset = decodeVarint( data[readPosition:readPosition+10] )
        readPosition += offset
        c0_bin = data[readPosition:readPosition+c0_len]
        readPosition += c0_len
        c0 = int( c0_bin.encode('hex') or '0', 16 )
        
        ss_len, offset = decodeVarint( data[readPosition:readPosition+10] )
        readPosition += offset
        ss = []
        for _ in range( ss_len ):
            s_len, offset = decodeVarint( data[readPosition:readPosition+10] )
            readPosition += offset
            s_bin = data[readPosition:readPosition+s_len]
            readPosition += s_len
            s = int( s_bin.encode('hex') or '0', 16 )
            ss.append( s )
            
        Y_tilde_x_len, offset = decodeVarint( data[readPosition:readPosition+10] )
        readPosition += offset
        Y_tilde_x_bin = data[readPosition:readPosition+Y_tilde_x_len]
        readPosition += Y_tilde_x_len
        Y_tilde_x = int( Y_tilde_x_bin.encode('hex') or '0', 16 )
        Y_tilde_y_len, offset = decodeVarint( data[readPosition:readPosition+10] )
        readPosition += offset
        Y_tilde_y_bin = data[readPosition:readPosition+Y_tilde_y_len]
        readPosition += Y_tilde_y_len
        Y_tilde_y = int( Y_tilde_y_bin.encode('hex') or '0', 16 )
        
        Y_tilde = Point( VotingData.CURVE, x=Y_tilde_x, y=Y_tilde_y )
        
        message_len, offset = decodeVarint( data[readPosition:readPosition+10] )
        readPosition += offset
        message = data[readPosition:readPosition+message_len]
#        readPosition += message_len

        return message, c0, ss, Y_tilde
    
    @staticmethod
    def get_all_awaiting_pubkey_for( address ):
        cps = ConsensusProtocol.get_all()
        cps = filter( lambda cp: cp.data is not None, cps )
        cps = filter( lambda cp: cp.data.type == ConsensusData.DATA_TYPE_VOTING, cps )
        cps = filter( lambda cp: address in cp.data.addresses, cps )
        return cps
    
    @staticmethod
    def public_key_received( address ):
        """
        Called when Bitmessage receives a new public key.
        
        Check if we have any elections waiting for a public key
        for the provided address, and reload the public keys of
        those elections.
        """
        awaiting_cps = VotingData.get_all_awaiting_pubkey_for( address )
        if len( awaiting_cps ) == 0:
            return
        
        for cp in awaiting_cps:
            cp.data.load_public_keys()
            cp.data.extract_signing_keys()
            cp.refresh_ui()
        
            
def log_debug(msg):
    if DEBUG:
        logger.debug("VotingData> %s" % msg)
def log_warn(msg):
    logger.warn( "VotingData> %s" % ( msg, ) )
        
