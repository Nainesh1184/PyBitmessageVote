'''
Created on 18/09/2014

@author: Jesper
'''
import hashlib, json, time
from pyelliptic.openssl import OpenSSL
from PyQt4.QtCore import QDateTime

from addresses import decodeAddress, encodeVarint, decodeVarint
from debug import logger
from helper_sql import sqlExecute, sqlQuery
import shared

from bitcoin_helper import BitcoinThread
from consensus_data import ConsensusData
from pyiblt import IBLT

# Set to True to log debug info
DEBUG = True

class ConsensusProtocol:
    CHAN_LABEL_PREFIX = '[consensus]'
    voteFileSection = 'CONSENSUS'
    
    STATUS_UNKNOWN = -1
    STATUS_NOT_OPEN_YET = 1
    STATUS_POSTING = 2
    STATUS_COMMITMENT_PHASE = 3
    STATUS_RESULTS_PHASE = 4
    
    MESSAGE_MESSAGE = 1
    MESSAGE_COMMITMENT = 2
    MESSAGE_RESULTS = 3
    
    MESSAGE_CONSENSUS_METADATA = 10
    
    MESSAGE_PHASE_CHANGE_POSTING = 1000
    MESSAGE_PHASE_CHANGE_COMMITMENT = 1001
    MESSAGE_PHASE_CHANGE_RESULTS = 1002
    
    MESSAGE_STATE_ACCEPTED = 1
    MESSAGE_STATE_RECEIVED_AFTER_DEADLINE = 2
    MESSAGE_STATE_UNVALIDATED_COMMITMENT = 11
    MESSAGE_STATE_PROCESSED = 12
    MESSAGE_STATE_NOT_PROCESSED = 13
    MESSAGE_STATE_INVALID_COMMITMENT = 14
    
    BLOCKCHAIN_BITCOIN = 1
    BLOCKCHAIN_BITCOIN_TESTNET = 2
    
    BLOCKCHAIN_NAMES = { BLOCKCHAIN_BITCOIN: "Bitcoin",
                         BLOCKCHAIN_BITCOIN_TESTNET: "Bitcoin TESTNET" }
    
    BLOCKCHAIN_CONFIRMATIONS_REQUIRED = 1
    ENCODING_TYPE = 12345
    
    # Set to True for testing without committing to and checking commitments on the blockchain
    # Should always be False, unless we're testing
    DISABLE_COMMITMENTS_ON_BLOCKCHAIN = True
    
    # Set to True to always react to MESSAGE_COMMITMENT_PHASE_* messages
    # regardless of whether it is actually true (disable double-checking with the blockchain)
    # Should always be False, unless we're testing
    DISABLE_CHECK_PHASE_CHANGE_MESSAGES = False

    # Set to True to first check if a commitment already exists on the blockchain
    # before committing to it ourselves. This could save a small amount of money
    # if the commitment already existed.    
    CHECK_IF_COMMITMENT_EXISTS_BEFORE_COMMITTING = False
    
    DEBUG = True
    
    instances = {}
    

    def __init__(self, id, message_hash, chan_address, data=None, settings=None, dont_check=False ):
        log_debug("__init__(%s)" % message_hash[:8])
        self.id = id
        
        self.chan_address = chan_address
        self.hash = message_hash
        self.data = data
        self.dont_check = dont_check
        self.initialized = False

        if settings is None:
            settings = {}
        self.settings = settings
        
        self.load_async()
        self.initialize_async()
        
        log_debug("__init__(%s) completed" % message_hash[:8])
        
    def refresh_status_from_latest_adjusted_timestamp(self):
        _, latest_timestamp, _ = BitcoinThread.get_latest_adjusted_timestamp( self.data.is_testnet_blockchain() )
        status = self.get_status()
        if latest_timestamp >= self.data.time_data.commitment_phase_deadline:
            if status < ConsensusProtocol.STATUS_RESULTS_PHASE:
                log_debug( "refresh_status() triggering results phase" )
                self.trigger_results_phase()
                    
        elif latest_timestamp >= self.data.time_data.post_deadline:
            if status < ConsensusProtocol.STATUS_COMMITMENT_PHASE:
                log_debug( "refresh_status() triggering commitment phase" )
                self.trigger_commitment_phase()
                
        elif latest_timestamp >= self.data.time_data.start:
            if status < ConsensusProtocol.STATUS_POSTING:
                log_debug( "refresh_status() triggering posting phase" )
                self.trigger_posting_phase()
                
                     
        
        
    @staticmethod
    def create( data ):
        """
        Creates a new ConsensusProtocol object with the provided time_data and data.
        Stores the object in the database.
        """
        hash = data.compute_hash()
        chan_address = ConsensusProtocol.compute_chan_address( hash )
        cp = ConsensusProtocol( None, hash, chan_address, data, dont_check=True )
    
    @staticmethod
    def join( hash ):
        """
        Join by hash - provide the hash, compute the chan address,
        start protocol in unknown mode, and wait for someone to broadcast
        the meta data
        """
        chan_address = ConsensusProtocol.compute_chan_address( hash )
        cp = ConsensusProtocol( None, hash, chan_address, dont_check=True )
        return cp
        
    @staticmethod
    def read_from_id(id):
        if id in ConsensusProtocol.instances:
            return ConsensusProtocol.instances[id]
        
        log_debug("read_from_id(%d)" % id)
        result = sqlQuery( 'SELECT chanaddress, hash, data, settings FROM consensus WHERE id=?', id )
        if result == []:
            return None
        
        chan_address, hash, data_bin, settings_json = result[0]
        if data_bin:
            data = ConsensusData.unpack_binary(data_bin, True)
        else:
            data = None
        
        result = ConsensusProtocol( id, hash, chan_address, data, json.loads( settings_json ), True )
        ConsensusProtocol.instances[id] = result
        return result
    
    @staticmethod
    def compute_chan_address(hash):
        """
        Compute the chan address from a hash
        """
        shared.apiAddressGeneratorReturnQueue.queue.clear()
        # command, addressVersionNumber, streamNumber, label, numberOfAddressesToMake, deterministicPassphrase, eighteenByteRipe
        shared.addressGeneratorQueue.put(('getDeterministicAddress', 4, 1, ConsensusProtocol.CHAN_LABEL_PREFIX, 1, hash, False))
        return shared.apiAddressGeneratorReturnQueue.get()
        
    def load_messages( self ):
        """
        Loads messages from the database.
        self.messages is a list of (time, message_type, message, message_hash, state)-tuples
        """
        messages = sqlQuery("SELECT local_time, message, message_hash, state FROM consensus_messages WHERE consensus_id=? ORDER BY message_hash", self.id )

        self.messages = map( lambda m: ( m[0], self.separate_message_type_and_message( m[1] ), m[2], m[3] ), messages )
        # Now self.messages is a list of ( time, (message_type, message ), message_hash, state )-tuples. We need to flatten the tuples
        self.messages = map( lambda m: ( m[0], m[1][0], m[1][1], m[2], m[3] ), self.messages )
        
    def filter_messages(self, message_type=None, state=None):
        """
        Filter the messages in self.messages by type and/or state.
        If a parameter is None, no filtering is performed on that parameter
        Returns is a list of (time, message_type, message, message_hash, state)-tuples
        """
        if message_type is not None:
            messages = filter( lambda m: m[1] == message_type, self.messages )
        if state is not None:
            messages = filter( lambda m: m[4] == state, messages )
            
        return messages
    
    def sort_loaded_messages(self):
        """
        Sorts the self.messages list in order of ascending hash
        """
        self.messages.sort(key=lambda m: m[3])

    def is_chan_already_joined(self):
        return self.chan_address != None and shared.config.has_section( self.chan_address )
    
    def load_async(self):
        shared.workerQueue.put( ('loadElection', self ) )
        
    def load(self):
        """
        Load a new consensus into the system.
        This includes joining the associated chan, and storing the consensus data in the DB.
        """
        
        if self.is_chan_already_joined():
            log_warn( "Consensus chan %s already joined. Wont join again" % self.chan_address )
        else:
            """
            Join the chan
            """        
            shared.apiAddressGeneratorReturnQueue.queue.clear()
            # command, chanAddress, label, deterministicPassphrase
            shared.addressGeneratorQueue.put(('joinChan', self.chan_address, ConsensusProtocol.CHAN_LABEL_PREFIX, self.hash))
            chan_addresses = shared.apiAddressGeneratorReturnQueue.get()
            if len( chan_addresses ) != 1 or chan_addresses[0] != self.chan_address:
                raise Exception( 'Invalid result from joinChan: %s' % chan_addresses )
            
            # Add extra voting parameter to the config file
            shared.config.set( self.chan_address, "consensus", 'true' )
            self.flush_shared_config()
        
        """
        Store in DB
        """
        self.store()
        
    def initialize_async(self):
        shared.workerQueue.put( ( 'initializeElection', self ) )
        
    def initialize(self):
        log_info( "Initializing election" )
        self.load_messages()
        
        self.__init_data__()
        
        if not self.dont_check:
            if self.data is not None:
                provided_hash = self.message_hash
                self.hash = self.data.compute_hash()
                if provided_hash is not None and self.hash != provided_hash:
                    raise Exception('Hash mismatch')
            
            provided_chan_address = self.chan_address
            self.chan_address = ConsensusProtocol.compute_chan_address( self.hash )
            if provided_chan_address is not None and self.chan_address != provided_chan_address:
                raise Exception('Chan address mismatch')
            
        self.initialized = True
        self.refresh_ui()
        shared.UISignalQueue.put(('election_initialized',(self, )))
        
    def __init_data__(self):
        if self.data is not None:
            self.data.cp = self
            self.data.initialize()
            
            """
            Ensure that we go to the right phase right away,
            in case we have been sleeping or something.
            """
            self.refresh_status_from_latest_adjusted_timestamp()
            self.setup_phase_change_alarms()
            self.data.status_changed( self.get_status() )
            
    def store(self):
        log_debug("store()")
        
        if self.data is not None:
            data_bin = self.data.pack_binary()
        else:
            data_bin = ""

        if self.id is None:
            # Insert new row
            t = (self.chan_address, self.hash, data_bin, json.dumps( self.settings ) )
            sqlExecute('INSERT INTO consensus (chanaddress, hash, data, settings) VALUES (?,?,?,?)', *t)
            
            id_query = "SELECT id FROM consensus WHERE hash=? AND data=? ORDER BY id DESC LIMIT 1"
            id_params = ( id_query, self.hash, data_bin )
            id_result = sqlQuery( *id_params )
            self.id = id_result[0][0]
            ConsensusProtocol.instances[self.id] = self
            
        else:
            # Update existing row
            t = (self.chan_address, self.hash, data_bin, json.dumps( self.settings ), self.id)
            sqlExecute('UPDATE consensus set chanaddress=?, hash=?, data=?, settings=? WHERE id=?', *t )
        
    def phase_change_alarm_callback(self, adjusted_timestamp, block_no):
        self.refresh_status_from_latest_adjusted_timestamp()
        
    def setup_phase_change_alarms(self):
        BitcoinThread.clear_alarms( self )
        
        status = self.get_status()
        
        timestamp = None
        if status == ConsensusProtocol.STATUS_NOT_OPEN_YET:
            # Wait for election to open
            timestamp = self.data.time_data.start
        elif status == ConsensusProtocol.STATUS_POSTING:
            # Wait for election to close
            timestamp = self.data.time_data.post_deadline
        elif status == ConsensusProtocol.STATUS_COMMITMENT_PHASE:
            # Wait for commitment phase to end
            timestamp = self.data.time_data.commitment_phase_deadline
            
        if timestamp is not None:
            BitcoinThread.enqueue(self, "setTimestampAlarm", [self.data.is_testnet_blockchain(), 
                                                              timestamp], 
                                  self.phase_change_alarm_callback )
    
    def get_status(self):
        """
        Function that defines the current status.
        
        Can return any of the STATUS_* constants:
        UNKNOWN, NOT_OPEN_YET, POSTING,
        COMMITMENT_PHASE, RESULTS_PHASE.
        """
        if self.data is None:
            return ConsensusProtocol.STATUS_UNKNOWN

        if self.settings_get_commitment_phase_end_block_number() is not None:
            return ConsensusProtocol.STATUS_RESULTS_PHASE
        elif self.settings_get_commitment_phase_block_number() is not None:
            return ConsensusProtocol.STATUS_COMMITMENT_PHASE
        elif self.settings_is_started():
            return ConsensusProtocol.STATUS_POSTING
        else:
            return ConsensusProtocol.STATUS_NOT_OPEN_YET
    
    def get_time_for_next_phase(self, status=None):
        """
        Return an amount of seconds left until the next phase,
        or None if we are missing the metadata or the consensus protocol
        has completed and is in the results phase.
        
        Time until the commitment and results phases are estimates
        given by the amount of blocks missing.
        """
        if status == None:
            status = self.get_status()
            
        if status == ConsensusProtocol.STATUS_UNKNOWN:
            return None
        
        td = self.data.time_data
        if status == ConsensusProtocol.STATUS_NOT_OPEN_YET:
            return BitcoinThread.estimate_seconds_until_adjusted_timestamp(self.data.is_testnet_blockchain(), td.start )
        elif status == ConsensusProtocol.STATUS_POSTING:
            return BitcoinThread.estimate_seconds_until_adjusted_timestamp(self.data.is_testnet_blockchain(), td.post_deadline )
        elif status == ConsensusProtocol.STATUS_COMMITMENT_PHASE:
            return BitcoinThread.estimate_seconds_until_adjusted_timestamp(self.data.is_testnet_blockchain(), td.commitment_phase_deadline )
        else:
            return None

    def refresh_ui(self):
        shared.UISignalQueue.put(('refresh_election_ui',(self, )))
    def update_status_bar(self, msg):
        shared.UISignalQueue.put( ('updateStatusBar', msg) )
            
    def post_message(self, data, message_type=MESSAGE_MESSAGE):
        """
        Broadcast a message to the chan from the chan address.
        
        data is the binary message, and message_type is the
        type identifier which will be prepended to the data.
        """
        ackdata = OpenSSL.rand(32)
        _, _, _, ripe = decodeAddress( self.chan_address )
        subject = ""
        
        # Append the message type in front of the data
        data = encodeVarint( message_type ) + data
        log_debug("post_message(type=%d, hash=%s)" % ( message_type, ConsensusProtocol.hash_message( data ).encode('hex' )[:8] ) )
        """
        SQL schema for the sent table:
        msgid blob, toaddress text, toripe blob, fromaddress text, subject text, message text, ackdata blob, lastactiontime integer, status text, pubkeyretrynumber integer, msgretrynumber integer, folder text, encodingtype int
        
        Notice the encodingType (last param) is special, so we can identify messages
        in the consensus protocol
        """
        t = ('', self.chan_address, ripe, self.chan_address, subject, data,
             ackdata, int(time.time()), 'msgqueued', 1, 1, 'sent', ConsensusProtocol.ENCODING_TYPE)
        sqlExecute( 'INSERT INTO sent VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', *t )
        shared.workerQueue.put(('sendmessage', self.chan_address))
        
    def received_message(self, message):
        """
        Called when a new message is received.
        What to do depends on the message type, which is
        encoded in the beginning of the message
        """
        message_type, data = self.separate_message_type_and_message( message )
        message_hash = ConsensusProtocol.hash_message( message )
        state = ConsensusProtocol.MESSAGE_STATE_ACCEPTED
        
        if self.data is None:
            # If we are waiting for the metadata, only allow the metadata message through
            # Discard all others
            if message_type == ConsensusProtocol.MESSAGE_CONSENSUS_METADATA:
                self.received_metadata_message( data )
                log_debug("received_message(type=%d, state=%d)" % ( message_type, state ) )
            else:
                log_debug("received_message discarded b/c of unknown metadata(type=%d, state=%d, hash=%s)" % ( message_type, state, message_hash.encode('hex')[:8] ) )
            return
        
        if message_type == ConsensusProtocol.MESSAGE_MESSAGE:
            if not self.data.message_valid( data ):
                log_debug("received_message invalid(type=%d, hash=%s)" % ( message_type, message_hash.encode('hex')[:8] ) )
                return
            
            """
            If we received the message after the commitment phase has begun,
            mark the message as arrived after the deadline, unless we already
            received a commitment to the new message
            """
            if message_hash in self.settings_get_missing_accepted_message_hashes():
                self.settings_remove_missing_accepted_message_hashes( message_hash )
                self.settings_add_messages_accepted_by_commitments( 1 )
            elif self.get_status() >= ConsensusProtocol.STATUS_COMMITMENT_PHASE:
                state = ConsensusProtocol.MESSAGE_STATE_RECEIVED_AFTER_DEADLINE
          
        elif message_type == ConsensusProtocol.MESSAGE_COMMITMENT:
            """
            Commitments are saved now and validated and processed
            when the commitment phase ends.
            """
            state = ConsensusProtocol.MESSAGE_STATE_UNVALIDATED_COMMITMENT
                  
        elif message_type == ConsensusProtocol.MESSAGE_RESULTS:
            self.received_results_message( data )
            
        elif message_type == ConsensusProtocol.MESSAGE_PHASE_CHANGE_POSTING:
            self.received_phase_change_posting_message( data )
        elif message_type == ConsensusProtocol.MESSAGE_PHASE_CHANGE_COMMITMENT:
            self.received_phase_change_commitment_message( data )
        elif message_type == ConsensusProtocol.MESSAGE_PHASE_CHANGE_RESULTS:
            self.received_phase_change_results_message( data )
        
        self.store_message( message_type, data, message_hash, state )
        
        self.refresh_ui()
        log_debug("received_message(type=%d, state=%d, hash=%s)" % ( message_type, state, message_hash.encode('hex')[:8] ) )
            
    def separate_message_type_and_message(self, data):
        """
        Takes a message encoded with the message type as
        a varint before the actual data,
        and separates the type from the data.
        """
        read_pos = 0
        
        message_type, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        
        message = data[read_pos:]
        return ( message_type, message )
        
    def store_message(self, message_type, data, message_hash, state=MESSAGE_STATE_ACCEPTED):
        """
        Store a message in the database and adds it to self.messages
        Check first if it exists (another message with the same hash exists),
        and UPDATE if it does, otherwise INSERT
        """
        queryresult = sqlQuery("SELECT local_time FROM consensus_messages WHERE consensus_id=? AND message_hash=?", self.id, message_hash )
        
        if len( queryresult ) > 0:
            # Already exists, let's update, but keep the time from the record
            # Only thing we can update is the state, so we'll do that
            sqlExecute( "UPDATE consensus_messages SET state=? WHERE consensus_id=? AND message_hash=?",
                        state, self.id, message_hash )
            time = queryresult[0][0]
            
            # Update the message in the self.messages list
            for i in range( len( self.messages ) ):
                time, m_type, m_data, m_hash, _ = self.messages[i]
                if m_hash == message_hash:
                    self.messages[i] = ( time, m_type, m_data, m_hash, state )
            
        else:
            time = QDateTime.currentMSecsSinceEpoch()
            message = encodeVarint( message_type ) + data
            params = ( self.id, time, message, message_hash, state )
            sqlExecute( 'INSERT INTO consensus_messages (consensus_id, local_time, message, message_hash, state) VALUES (?,?,?,?,?)', *params )
            self.messages.append( ( time, message_type, data, message_hash, state ) )
            
        log_debug("store_message(type=%d, state=%d, time=%d, hash=%s, insert_new=%s)" % ( message_type, state, time, message_hash.encode('hex')[:8], len( queryresult ) == 0 ) )
        return ( time, message_type, data, message_hash, state )
    
    def broadcast_consensus_metadata(self):
        """
        Sends a MESSAGE_CONSENSUS_METADATA message out to the chan
        with the consensus metadata to whoever may not have it
        because they joined simply by entering the hash.
        """
        self.post_message( self.pack_binary(), ConsensusProtocol.MESSAGE_CONSENSUS_METADATA )
    
    def debug_clear_messages(self):
        """
        Clears all messages related to this consensus protocol.
        Should only be used for testing purposes
        """
        if self.id is None:
            return
        self.settings_set_commitment_phase_block_number( None )
        self.settings_set_commitment_phase_end_block_number( None )
        self.settings_set_has_sent_commitment( False )
        self.settings_set_has_sent_results( False )
        self.settings_set_missing_accepted_message_hashes( [] )
        self.messages = []
        sqlExecute( "DELETE FROM consensus_messages WHERE consensus_id=?", self.id )
        
    def debug_trigger_posting_phase(self, broadcast=False):
        if broadcast and not ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES:
            log_warn( "Set ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES=True to do this" )
            return
        self.trigger_posting_phase( 1 )
        if broadcast:
            self.post_message( "", ConsensusProtocol.MESSAGE_PHASE_CHANGE_POSTING )
        
    def debug_revoke_posting_phase(self):
        self.settings_set_is_started( False )
        
        """
        Delete all messages
        """
        for _, _, _, message_hash, _ in self.filter_messages(ConsensusProtocol.MESSAGE_MESSAGE):
            self.debug_delete_message( message_hash )

        self.setup_phase_change_alarms()
        self.data.status_changed( self.get_status() )
        
        
    def debug_trigger_commitment_phase(self, broadcast=False):
        if broadcast and not ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES:
            log_warn( "Set ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES=True to do this" )
            return
        self.trigger_commitment_phase( 2 )
        if broadcast:
            self.post_message( "", ConsensusProtocol.MESSAGE_PHASE_CHANGE_COMMITMENT )

    def debug_revoke_commitment_phase(self):
        self.settings_set_commitment_phase_block_number( None )
        self.settings_set_has_sent_commitment( False )

        for _, _, _, message_hash, _ in self.filter_messages(ConsensusProtocol.MESSAGE_COMMITMENT ):
            self.debug_delete_message( message_hash )

        self.setup_phase_change_alarms()
        self.data.status_changed( self.get_status() )

    def debug_trigger_results_phase(self, broadcast=False):
        if broadcast and not ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES:
            log_warn( "Set ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES=True to do this" )
            return
        
        self.trigger_results_phase( 9999999 )
        if broadcast:
            data = ConsensusProtocol.pack_commitment_phase_ended_message( 9999999 )
            self.post_message( data, ConsensusProtocol.MESSAGE_PHASE_CHANGE_RESULTS )
        
    def debug_revoke_results_phase(self):
        self.settings_set_commitment_phase_end_block_number( None )
        self.settings_set_has_sent_results( False )
        
        for _, message_type, data, message_hash, _ in self.filter_messages(ConsensusProtocol.MESSAGE_COMMITMENT ):
            self.store_message( message_type, data, message_hash, ConsensusProtocol.MESSAGE_STATE_UNVALIDATED_COMMITMENT )
        for _, _, _, message_hash, _ in self.filter_messages(ConsensusProtocol.MESSAGE_RESULTS ):
            self.debug_delete_message( message_hash )
            
        self.setup_phase_change_alarms()
        self.data.status_changed( self.get_status() )
            
            
    def debug_delete_message(self, message_hash ):
        """
        Deletes a message from the database by its hash
        """
        sqlExecute( "DELETE FROM consensus_messages WHERE consensus_id=? AND message_hash=?", self.id, message_hash )
        self.messages = [m for m in self.messages if m[3] != message_hash]
    
    @staticmethod    
    def hash_message(message):
        """
        Hash something using SHA-256 and return the binary digest
        """
        sha = hashlib.new( 'sha256' )
        sha.update( message )
        return sha.digest()
        
    def get_all_messages(self):
        """
        Returns a list of (time, message) for all ordinary, accepted messages.
        """
        ordinary_messages = self.filter_messages( ConsensusProtocol.MESSAGE_MESSAGE, ConsensusProtocol.MESSAGE_STATE_ACCEPTED )
        return map( lambda m: ( m[0], m[2] ), ordinary_messages  )
    
    def received_metadata_message(self, data):
        if self.get_status() != ConsensusProtocol.STATUS_UNKNOWN:
            # If we already have the metadata, discard this message
            return
        new_hash, new_chan_address, new_data = ConsensusProtocol.unpack_binary( data )
        
        if self.hash != new_hash or self.chan_address != new_chan_address:
            log_warn( "Received metadata mismatch! %s!=%s OR %s!=%s" % ( repr( self.hash), repr( new_hash), repr( self.chan_address), repr( new_chan_address ) ) )
            return
        
        self.data = new_data
        self.__init_data__()
        self.store()
        log_info( "Received metadata correctly." )
        self.refresh_ui()
    
    def received_phase_change_posting_message(self, data):
        if not ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES:
            block_no = None
        else:
            block_no = 1
            
        self.trigger_posting_phase( block_no )
    
    def trigger_posting_phase(self, block_no=None):
        """
        If block_no is None, check with the blockchain if the timestamp has been reached
        """
        if self.get_status() != ConsensusProtocol.STATUS_NOT_OPEN_YET:
            return
        
        if block_no is None:
            block_no = BitcoinThread.get_first_block_with_adjusted_timestamp( self.data.is_testnet_blockchain(), self.data.time_data.start )
            if block_no is None:
                return
        
        self.settings_set_is_started(True)
        self.setup_phase_change_alarms()
        self.data.status_changed( self.get_status() )
        self.refresh_ui()
        
    def received_phase_change_commitment_message(self, data):
        if not ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES:
            block_no = None
        else:
            block_no = 2
        
        self.trigger_commitment_phase( block_no )
    
    def trigger_commitment_phase(self, block_no=None ):
        # Ensure that we are actually not yet in the commitment phase
        if self.get_status() > ConsensusProtocol.STATUS_POSTING:
            return
        
        if block_no is None:
            block_no = BitcoinThread.get_first_block_with_adjusted_timestamp( self.data.is_testnet_blockchain(), self.data.time_data.post_deadline )
            if block_no is None:
                return
        
        # Remember to set the commitment phase block number BEFORE
        # setting up alarms
        self.settings_set_commitment_phase_block_number( block_no )
        self.setup_phase_change_alarms()
        self.data.status_changed( self.get_status() )
        log_info( "Commitment phase begun at block %d" % ( block_no ) )
        
        # Only timestampers participate in the commitment phase
        if self.settings_is_timestamper():
            if not self.settings_has_sent_commitment():
                self.do_commitment()
            
        self.refresh_ui()
            
        
    def do_commitment(self):
        """
        Compute a commitment based on the list of accepted messages.
            Later, check if the same list has already been committed to
            on the blockchain and do so if it hasn't.
        Also, broadcast the intermediate commitment to the chan:
        (Hash of list, IBLT of message hashes)
        """
        self.sort_loaded_messages()
        
        # self.messages is a list of (time, message_type, message, message_hash, state)-tuples
        accepted_messages = self.filter_messages( message_type=ConsensusProtocol.MESSAGE_MESSAGE, state=ConsensusProtocol.MESSAGE_STATE_ACCEPTED )
        message_hashes = map( lambda m: m[3], accepted_messages )
        
        # Normalize the list so everybody with the same messages will get the same IBLT
        message_hashes.sort()
        iblt = self.create_iblt( message_hashes )
        iblt_hash = ConsensusProtocol.hash_message( iblt.serialize() )

        log_debug("do_commitment(accepted_messages=%d)" % ( len( accepted_messages ) ) )
        
        if not ConsensusProtocol.DISABLE_COMMITMENTS_ON_BLOCKCHAIN and self.settings_is_timestamper():
            """
            Before we commit, let's check if somebody already did it before us.
            If that is the case, there is no need for us to spend money committing to the same content.
            Note that we only check for confirmed transactions. This means that it is possible
            for many nodes to commit somewhat simultaneously because the others' commitments
            haven't been confirmed at the time.
            """
            commit_address = BitcoinThread.get_address( self.data.is_testnet_blockchain(), iblt_hash )
            
            perform_commit = True
            if ConsensusProtocol.CHECK_IF_COMMITMENT_EXISTS_BEFORE_COMMITTING:
                first_seen = BitcoinThread.get_first_seen( self.data.is_testnet_blockchain(), commit_address )
                if first_seen is not None:
                    _, tx_confirmation_count, _ = first_seen
                    if tx_confirmation_count >= ConsensusProtocol.BLOCKCHAIN_CONFIRMATIONS_REQUIRED:
                        log_debug("Didn't commit to %s, already existed" % commit_address )
                        perform_commit = False
                    
            if perform_commit:
                _, commit_addresses = self.settings_get_timestamper_settings()
                for _, private_key, btc_address in commit_addresses:
                    commit_result = BitcoinThread.commit_to( self.data.is_testnet_blockchain(), commit_address, private_key )
                    
                    log_debug("do_commitment to %s with address %s: %s" % ( commit_address, btc_address, "SUCCESS" if commit_result else "FAILURE" ) )
            
        message = ConsensusProtocol.pack_commitment_message(iblt_hash, iblt)
        self.post_message( message, ConsensusProtocol.MESSAGE_COMMITMENT )
        
        self.settings_set_has_sent_commitment( True )
        
    def compute_list_hash(self, l):
        """
        Computes the hash of a list of elements by concatenating them.
        """
        joined_elements = "".join( l )
        return ConsensusProtocol.hash_message( joined_elements )
    
    def create_iblt(self, hashes):
        """
        Creates an Invertible Bloom Lookup Table (IBLT) with the
        given list of hashes.
        The parameters for the IBLT is as follows:
            t (threshold value): 10
            k (amount hash functions): 4
            m (amount of cells): 10*1.425 = 15 (k=4 => m=t*1.425)
            key_size: 32
            value_size: 0
            hash_key_sum_size: 8
        """
        t = IBLT( 15, 4, 32, 0, 8 )
        for h in hashes:
            t.insert( h, "" )
        return t
    
    def validate_commitment_messages(self):
        """
        Validate all unvalidated commitment messages.
        Commitment messages with MESSAGE_STATE_UNVALIDATED_COMMITMENT state
        will have their state updated to either
        MESSAGE_STATE_NOT_PROCESSED if valid or
        MESSAGE_STATE_INVALID_COMMITMENT if invalid
        
        This method also checks the commitment on the blockchain, so
        it shouldn't be run right after receiving a commitment message,
        since it probably won't have enough confirmations.
        
        Run it when the commitment phase ends. 
        """
        
        not_validated_commitments = self.filter_messages(ConsensusProtocol.MESSAGE_COMMITMENT, ConsensusProtocol.MESSAGE_STATE_UNVALIDATED_COMMITMENT)
        for _, _, data, message_hash, _ in not_validated_commitments:
            iblt_hash, iblt = ConsensusProtocol.unpack_commitment_message( data )
            log_debug( "Validating commitment %s" % message_hash.encode('hex')[:8] )
            
            """
            Check that the provided hash matches the actual hash of the IBLT
            """ 
            iblt_hash_computed = ConsensusProtocol.hash_message( iblt.serialize() )
            if iblt_hash != iblt_hash_computed:
                # Hashes don't match. Invalid commitment.
                log_warn( "Hash mismatch '%s' != '%s'" % ( iblt_hash.encode('hex'), iblt_hash_computed.encode('hex') ) )
                self.store_message( ConsensusProtocol.MESSAGE_COMMITMENT, data, message_hash, ConsensusProtocol.MESSAGE_STATE_INVALID_COMMITMENT )
                continue
            
            """
            Check that the included IBLT actually has been committed to on the blockchain,
            and that the commitment happened before the commitment phase ended.
            """
            if not ConsensusProtocol.DISABLE_COMMITMENTS_ON_BLOCKCHAIN:
                address = BitcoinThread.get_address( self.data.is_testnet_blockchain(), iblt_hash )
                # first_seen = None or ( block_number, confirmation_count, block_timestamp ) 
                first_seen = BitcoinThread.get_first_seen( self.data.is_testnet_blockchain(), address )
                if first_seen is None:
                    log_warn( "Address %s wasn't found on the blockchain. Invalid commitment." % address )
                    self.store_message( ConsensusProtocol.MESSAGE_COMMITMENT, data, message_hash, ConsensusProtocol.MESSAGE_STATE_INVALID_COMMITMENT )
                    continue
                
                """
                Check that the commitment tx was included in a block before the commitment phase was over
                and that it has at least the required amount of confirmations
                """
                tx_block_no, tx_confirmation_count, _ = first_seen
                end_block_no = self.settings_get_commitment_phase_end_block_number()
                
                log_debug( "process_commitment()_2: %d, %d, %d" % ( end_block_no, tx_confirmation_count, ConsensusProtocol.BLOCKCHAIN_CONFIRMATIONS_REQUIRED ) )
                if tx_block_no >= end_block_no:
                    log_warn( "Address %s was committed to too late: tx block no: %d, commitment phase end block: %d" % ( address, tx_block_no, end_block_no ) )
                    self.store_message( ConsensusProtocol.MESSAGE_COMMITMENT, data, message_hash, ConsensusProtocol.MESSAGE_STATE_INVALID_COMMITMENT )
                    continue
                
                elif tx_confirmation_count < ConsensusProtocol.BLOCKCHAIN_CONFIRMATIONS_REQUIRED:
                    log_warn( "Insufficient confirmations on tx: (%d/%d) address: %s" % ( tx_confirmation_count, ConsensusProtocol.BLOCKCHAIN_CONFIRMATIONS_REQUIRED, address ) )
                    self.store_message( ConsensusProtocol.MESSAGE_COMMITMENT, data, message_hash, ConsensusProtocol.MESSAGE_STATE_INVALID_COMMITMENT )
                    continue
               
            """
            Everthing was validated. Save as not processed
            """
            self.store_message( ConsensusProtocol.MESSAGE_COMMITMENT, data, message_hash, ConsensusProtocol.MESSAGE_STATE_NOT_PROCESSED )
                    
            
    def process_commitment_messages(self):
        """
        Process all validated, not-processed commitments.
        
        First, extract as many hashes as possible from the commitment IBLTs (steps 1-3).
        Then mark too late messages with hashes from the IBLTs as received timely (step 4). 
        
        missing_valid_hashes is a list of known valid message hashes which we don't
            already have the message for.
        valid_hashes is a list of all known valid message hashes
            (from accepted messages and from processing IBLTs)
        new_hashes is a new temporary, empty list
        
        (1) While there exists a not processed IBLT T for which (T - valid_hashes).LIST_ENTRIES() 
                returns one or more hashes not present in either valid_hashes or new_hashes, do the following:
            (a) (Result, Hashes) = (T - valid_hashes).LIST_ENTRIES}()
            (b) Add the hashes to new_hashes
            (c) If Result == Complete, mark T as processed.
        (2) Copy the new hashes from new_hashes to valid_hashes and missing_valid_hashes, and clear the new_hashes list
        (3) If any unprocessed IBLT's still exist and at least one hash was moved from new_hashes in the previous step, go back to step 1.
        (4) For each message flagged as being sent after the deadline whose hash is in missing_valid_hashes, flag it as being sent before the deadline.
        """
        
        missing_valid_hashes = self.settings_get_missing_accepted_message_hashes()
        accepted_messages = self.filter_messages( ConsensusProtocol.MESSAGE_MESSAGE, ConsensusProtocol.MESSAGE_STATE_ACCEPTED )
        valid_hashes = map( lambda msg: msg[3], accepted_messages )
        valid_hashes.extend( missing_valid_hashes )
        new_hashes = []
        
        unprocessed_commitments = self.filter_messages(ConsensusProtocol.MESSAGE_COMMITMENT, ConsensusProtocol.MESSAGE_STATE_NOT_PROCESSED)
        log_debug( "Processing %d commitment messages (%d already valid hashes)" % ( len( unprocessed_commitments ), len( valid_hashes ) ) )
        
        new_hashes_added = True
        while any( unprocessed_commitments ) and new_hashes_added:
            new_hashes = []
            
            """
            Step (1)
            """
            for commitment in unprocessed_commitments:
                _, _, commitment_data, commitment_message_hash, _ = commitment
                _, iblt = ConsensusProtocol.unpack_commitment_message( commitment_data )
                for message_hash in valid_hashes:
                    iblt.delete( message_hash, "" )
                    
                """
                Step (1a)
                """
                iblt_result, entries, _ = iblt.list_entries()
                
                # A list of all extractable hashes in the IBLT
                iblt_hashes = map( lambda (k, v) : k, entries )
                # A list of all hashes which we didn't already have
                iblt_new_hashes = filter( lambda h: h not in valid_hashes and h not in new_hashes, iblt_hashes )
                """
                Step (1) condition. If the IBLT doesn't have any new messages,
                try the others. If none do, go to step (4) 
                """
                if not any( iblt_new_hashes ):
                    continue
                
                """
                Step (1b)
                """
                new_hashes.extend( iblt_new_hashes )
                
                """
                Step (1c)
                """
                if iblt_result == IBLT.RESULT_LIST_ENTRIES_COMPLETE:
                    unprocessed_commitments.remove( commitment )
                    self.store_message( ConsensusProtocol.MESSAGE_COMMITMENT, commitment_data, commitment_message_hash, ConsensusProtocol.MESSAGE_STATE_PROCESSED )
                
            if any( new_hashes ):
                """
                Step (2)
                """
                log_debug( "New valid hashes: %s" % ( map( lambda h: h.encode('hex')[:8], new_hashes ), ) )
                missing_valid_hashes = missing_valid_hashes.union( new_hashes )
                valid_hashes.extend( new_hashes )
                new_hashes = []
                
                """
                Step (3)
                """
                new_hashes_added = True
            else:
                new_hashes_added = False
                
                
        """
        Step (4)
        """
        too_late_messages = self.filter_messages( ConsensusProtocol.MESSAGE_MESSAGE, ConsensusProtocol.MESSAGE_STATE_RECEIVED_AFTER_DEADLINE )
        messages_accepted = 0
        for _, _, data, message_hash, _ in too_late_messages:
            if message_hash in missing_valid_hashes:
                self.store_message(ConsensusProtocol.MESSAGE_MESSAGE, data, message_hash, ConsensusProtocol.MESSAGE_STATE_ACCEPTED)
                messages_accepted += 1
                missing_valid_hashes.remove( message_hash )
                
        if messages_accepted > 0:
            self.settings_add_messages_accepted_by_commitments( messages_accepted )
            self.refresh_ui()
            
        log_debug( "Accepted %d messages after processing IBLT's" % messages_accepted )

        self.settings_extend_missing_accepted_message_hashes( missing_valid_hashes )
            
    
    def received_phase_change_results_message(self, data):
        if ConsensusProtocol.DISABLE_CHECK_PHASE_CHANGE_MESSAGES:
            block_no = ConsensusProtocol.unpack_commitment_phase_ended_message( data )
        else:
            block_no = None
            
        self.trigger_results_phase( block_no )
    
    def trigger_results_phase(self, block_no=None):
        # Ensure that we are actually in the commitment phase
        if self.get_status() > ConsensusProtocol.STATUS_COMMITMENT_PHASE:
            return
        
        if block_no is None:
            block_no = BitcoinThread.get_first_block_with_adjusted_timestamp( self.data.is_testnet_blockchain(), self.data.time_data.commitment_phase_deadline )
            if block_no is None:
                return
            
        
        self.settings_set_commitment_phase_end_block_number( block_no )
        log_info( "Commitment phase ended with block %d" % ( block_no ) )
        
        self.validate_commitment_messages()
        self.process_commitment_messages()
        
        """
        Calculate final commitment and results, and post these
        """
        if not self.settings_has_sent_results():
            # self.messages is a list of (time, message_type, message, message_hash, state)-tuples
            accepted_messages = self.filter_messages( message_type=ConsensusProtocol.MESSAGE_MESSAGE,
                                                      state=ConsensusProtocol.MESSAGE_STATE_ACCEPTED )
            message_hashes = map( lambda m: m[3], accepted_messages )
            # Normalize the list so everybody with the same messages will get the same list hash
            message_hashes.sort()
            
            list_hash = self.compute_list_hash( message_hashes )
            
            message_contents = map( lambda m: ( m[0], m[2] ), accepted_messages )
            results = self.data.compute_results( message_contents )
    
            data = ConsensusProtocol.pack_results_message(list_hash, results)
            self.post_message( data, ConsensusProtocol.MESSAGE_RESULTS )
            
            self.settings_set_has_sent_results( True )
        
        self.refresh_ui()
        
    def received_results_message(self, data):
        list_hash, results = ConsensusProtocol.unpack_results_message( data )
        log_info("received_result_commitment(results=%s)" % ( results ) )
        
    def subtract_message_hashes_from_iblt(self, iblt):
        """
        Clone the provided IBLT, subtract all our accepted messages from it,
        and return it.
        """
        # Create a copy of the IBLT
        iblt = IBLT.unserialize( iblt.serialize() )
        accepted_messages = self.filter_messages( ConsensusProtocol.MESSAGE_MESSAGE, ConsensusProtocol.MESSAGE_STATE_ACCEPTED )
        
        log_debug( "SUBTRACT_IBLT subtract %s" % ( map(lambda am: am[3].encode('hex_codec')[:6], accepted_messages ),) )
        for _, _, _, message_hash, _ in accepted_messages:
            iblt.delete( message_hash, '' )
            
        return iblt
        
    def settings_get_timestamper_settings(self):
        # Returns ( enabled, [ ( bm_address, private_key, btc_address ) ] )
        result = ( False, [] )
        if "timestamper" in self.settings:
            result = self.settings["timestamper"]
            
            # Legacy line, remove when all election databases uses the new notation
            if result in (True, False): return ( False, [] )
            
            enabled, addresses = result
            # Remember to decode the private keys
            result = ( enabled, map( lambda addr: ( addr[0], addr[1].decode('hex') , addr[2]), addresses ) )
        return result
    def settings_set_timestamper_settings(self, enabled, addresses):
        # addresses is list of ( bm_address, private_key, btc_address )-tuples
        # We'll remember to encode the private key
        addresses = map( lambda addr: ( addr[0], addr[1].encode('hex'), addr[2] ), addresses )
        self.settings["timestamper"] = ( enabled, addresses )
        self.store()
    def settings_is_timestamper(self):
        return self.settings_get_timestamper_settings()[0]
        
    def settings_get_commitment_phase_block_number(self):
        return self.settings["commitment_phase_bn"] if "commitment_phase_bn" in self.settings else None
    def settings_set_commitment_phase_block_number(self, block_no):
        self.settings["commitment_phase_bn"] = block_no
        self.store()
        
    def settings_is_started(self):
        return self.settings["started"] if "started" in self.settings else False        
    def settings_set_is_started(self, started):
        self.settings["started"] = started
        self.store()
        
    def settings_get_commitment_phase_end_block_number(self):
        return self.settings["commitment_phase_end_bn"] if "commitment_phase_end_bn" in self.settings else None
    def settings_set_commitment_phase_end_block_number(self, block_no):
        self.settings["commitment_phase_end_bn"] = block_no
        self.store()
                
    def settings_has_sent_commitment(self):
        return self.settings["cs"] if "cs" in self.settings else False
    def settings_set_has_sent_commitment(self, sent):
        self.settings["cs"] = sent
        self.store()
    def settings_has_sent_results(self):
        return self.settings["rs"] if "rs" in self.settings else False
    def settings_set_has_sent_results(self, sent):
        self.settings["rs"] = sent
        self.store()
                
    def settings_get_missing_accepted_message_hashes(self):
        encoded_list = self.settings["mamh"] if "mamh" in self.settings and self.settings['mamh'] is not None else []
        return set( map( lambda mh: mh.decode('hex_codec'), encoded_list ) )
    def settings_set_missing_accepted_message_hashes(self, hash_list):
        self.settings["mamh"] = map( lambda mh: mh.encode('hex_codec'), hash_list )
        self.store()
    def settings_extend_missing_accepted_message_hashes(self, iterable):
        new_set = self.settings_get_missing_accepted_message_hashes().union( iterable )
        self.settings_set_missing_accepted_message_hashes( new_set )
    def settings_remove_missing_accepted_message_hashes(self, message_hash):
        new_set = self.settings_get_missing_accepted_message_hashes()
        new_set.remove( message_hash )
        self.settings_set_missing_accepted_message_hashes( new_set )
    def settings_add_messages_accepted_by_commitments(self, amount):
        self.settings_set_messages_accepted_by_commitments( amount + self.settings_get_messages_accepted_by_commitments() )
    def settings_set_messages_accepted_by_commitments(self, amount):
        self.settings["mabc"] = amount
        self.store()
    def settings_get_messages_accepted_by_commitments(self):
        return self.settings["mabc"] if "mabc" in self.settings else 0
                
    def to_json(self):
        return { "hash": self.hash, "chan_address": self.chan_address, "settings": self.settings,
                 "data": self.data.to_json() }
    
    def pack_binary(self):
        # Hash, ChanAddress, TimeData, Data 
        result = ""
        result += encodeVarint( len( self.hash ) )
        result += self.hash
        
        result += encodeVarint( len( self.chan_address ) )
        result += self.chan_address
        
        data_bin = self.data.pack_binary() 
        result += encodeVarint( len( data_bin ) )
        result += data_bin
        
        return result
    
    @staticmethod
    def unpack_binary(data, dont_check=False):
        # Hash, ChanAddress, TimeData, Data 
        
        read_pos = 0
        
        hash_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        hash = data[read_pos:read_pos+hash_len]
        read_pos += hash_len
        
        chan_address_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        chan_address = data[read_pos:read_pos+chan_address_len]
        read_pos += chan_address_len
        
        data_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        data_bin = data[read_pos:read_pos+data_len]
        read_pos += data_len
        data = ConsensusData.unpack_binary( data_bin, dont_check )
        
        return hash, chan_address, data
    
    @staticmethod
    def pack_commitment_message( iblt_hash, iblt ):
        """
        Packs a commitment message into a binary string.
        The format is
        [ list_hash_length(varInt) ][ iblt_hash ]
        [ iblt_length(varInt) ][ iblt_serialized ]
        """
        result = ""
        
        iblt_serialized = iblt.serialize()
        
        result += encodeVarint( len( iblt_hash ) )
        result += iblt_hash
        
        result += encodeVarint( len( iblt_serialized ) )
        result += iblt_serialized
    
        return result
    
    @staticmethod
    def unpack_commitment_message( data ):
        read_pos = 0
        
        iblt_hash_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        iblt_hash = data[read_pos:read_pos+iblt_hash_len]
        read_pos += iblt_hash_len
        
        iblt_serialized_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        iblt_serialized = data[read_pos:read_pos+iblt_serialized_len]
        read_pos += iblt_serialized_len
        
        iblt = IBLT.unserialize( iblt_serialized )
        
        return ( iblt_hash, iblt )
        
    @staticmethod
    def pack_results_message( list_hash, results ):
        """
        Packs a result commitment message into a binary string.
        The format is
        [ list_hash_length(varInt) ][ list_hash ]
        [ results_length(varInt) ][ results ]
        """
        result = ""
        
        result += encodeVarint( len( list_hash ) )
        result += list_hash
        
        result += encodeVarint( len( results ) )
        result += results
    
        return result
    
    @staticmethod
    def unpack_results_message( data ):
        read_pos = 0
        
        list_hash_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        list_hash = data[read_pos:read_pos+list_hash_len]
        read_pos += list_hash_len
        
        results_len, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        results = data[read_pos:read_pos+results_len]
        read_pos += results_len
        
        return ( list_hash, results )
    
    @staticmethod
    def pack_commitment_phase_ended_message( block_no ):
        """
        Packs a COMMITMENT_PHASE_ENDED message with the block number
        of the start of the results phase.
        The format is
        [ block_no(varInt) ]
        """
        result = ""
        
        result += encodeVarint( block_no )
        
        return result

    @staticmethod
    def unpack_commitment_phase_ended_message( data ):
        read_pos = 0
        
        block_no, offset = decodeVarint( data[read_pos:read_pos+10] )
        read_pos += offset
        
        return block_no
    
    def saveToFile(self, filename):
        result = self.pack_binary()
        with open( filename, 'wb' ) as f:
            f.write( result )
            
    def delete(self):
#        if not self.is_chan_already_joined():
#            return
        
        shared.config.remove_section( self.chan_address )
        self.flush_shared_config()
        
        sqlExecute('DELETE FROM consensus_messages WHERE consensus_id=?', self.id)
        sqlExecute('DELETE FROM consensus WHERE id=?', self.id)
        
    def flush_shared_config(self):
        with open(shared.appdata + 'keys.dat', 'w') as configfile:
            shared.config.write(configfile)
            
    @staticmethod   
    def read_from_file(filename):
        log_info( "Reading consensus data from %s" % (filename) )
        with open( filename, 'rb' ) as f:
            data = f.read()
            log_debug( "Filesize: %d" % len ( data ) )
            new_hash, new_chan_address, new_data = ConsensusProtocol.unpack_binary( data, False )
            result = ConsensusProtocol.read_from_address( new_chan_address ) 
        
            if result is not None:
                if result.hash != new_hash or result.chan_address != new_chan_address:
                    log_warn( "Imported metadata mismatch! %s!=%s OR %s!=%s" % ( repr( result.hash), repr( new_hash), repr( result.chan_address), repr( new_chan_address ) ) )
                    return
                
                result.data = new_data
                result.__init_data__()
                result.store()
                
            else:
                result = ConsensusProtocol( None, new_hash, new_chan_address, new_data )
                
            log_debug( "Imported metadata correctly." )
            return result
        
    @staticmethod
    def get_all_ids():
        return map( lambda x: x[0], sqlQuery( 'SELECT id FROM consensus' ) )
    
    @staticmethod
    def get_all():
        return map( lambda id: ConsensusProtocol.read_from_id( id ), ConsensusProtocol.get_all_ids() )
    
    @staticmethod
    def read_from_address(address):
        queryResult = sqlQuery( "SELECT id FROM consensus WHERE chanaddress=?", address )
        if queryResult == []:
            return None
        else:
            return ConsensusProtocol.read_from_id( queryResult[0][0] )
        
    def __eq__(self, other):
        return other is not None and self.id == other.id
         
    def __str__(self):
        return "ConsensusProtocol<%d,(%s,%s)>" % ( self.id or -1, self.chan_address, self.hash )



def log_debug(msg):
    if DEBUG:
        logger.debug("ConsensusProtocol> %s" % msg)
        
def log_info(msg):
    if DEBUG:
        logger.info("ConsensusProtocol> %s" % msg)
        
def log_warn(msg):
    if DEBUG:
        logger.warn("ConsensusProtocol> %s" % msg)
        
def log_error(msg):
    if DEBUG:
        logger.error("ConsensusProtocol> %s" % msg)
        
